package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
)

// runKnowledge dispatches the `knowledge` subcommands.
func runKnowledge(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s knowledge import <files or dirs>", branding.CLI)
	}
	switch args[0] {
	case "import":
		return runKnowledgeImport(args[1:])
	default:
		return fmt.Errorf("unknown knowledge subcommand %q (want: import)", args[0])
	}
}

// runKnowledgeImport seeds the SOP corpus from existing institutional
// knowledge (design/06 §2.4): markdown files with optional YAML frontmatter
// carrying attribution. Conversion from richer formats stays client-side by
// design — export Confluence/Word/PDF to markdown first (pandoc does all
// three); the backend only ever receives clean text + structured attribution.
//
// Re-import is an upsert: the source URL (frontmatter source.url, defaulting
// to file:<path>) keys the lineage, so importing an updated document revises
// the SOP in place — the prior version stays hash-addressable for audit.
func runKnowledgeImport(args []string) error {
	fl := flag.NewFlagSet("knowledge import", flag.ContinueOnError)
	user := fl.String("user", envOrDefault("RECKON_USER", branding.CLI+"-admin"), "backend login user (or RECKON_USER)")
	pass := fl.String("password", os.Getenv("RECKON_PASSWORD"), "backend login password (or RECKON_PASSWORD)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	paths := fl.Args()
	if len(paths) == 0 {
		return fmt.Errorf("usage: %s knowledge import [-user u] [-password p] <file-or-dir>...\n  files: .md/.markdown/.txt with optional YAML frontmatter (title, author, tags, recommendation, source{system,url,version})\n  richer formats: convert first, e.g. `pandoc runbook.docx -t gfm`", branding.CLI)
	}
	if *pass == "" {
		*pass = branding.CLI // the dev-auth default, same as the eval harness
	}

	files, err := collectImportFiles(paths)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no importable files (.md/.markdown/.txt) under %s", strings.Join(paths, ", "))
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	backendURL := fmt.Sprintf("http://localhost:%d", cfg.Backend.HTTPPort)
	issuer := fmt.Sprintf("http://localhost:%d/realms/%s", cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cred, err := agent.NewCredential(ctx, issuer, branding.CLI, *user, *pass)
	if err != nil {
		return fmt.Errorf("login: %w\n  hint: the shipped realm has no login user and ROPC is off — run `%s dev-auth` first", err, branding.CLI)
	}

	failed := 0
	for _, path := range files {
		doc, err := parseSOPDocument(path)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  FAIL  %s — %v\n", path, err)
			continue
		}
		outcome, err := postSOPImport(ctx, cred, backendURL, doc)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  FAIL  %s — %v\n", path, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-7s %s — %q\n", outcome, path, doc.Title)
	}
	fmt.Fprintf(os.Stderr, "%s: imported %d/%d file(s)\n", branding.CLI, len(files)-failed, len(files))
	if failed > 0 {
		return fmt.Errorf("%d file(s) failed", failed)
	}
	return nil
}

// collectImportFiles expands files and directories into the importable set.
func collectImportFiles(paths []string) ([]string, error) {
	var out []string
	importable := func(name string) bool {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".md", ".markdown", ".txt":
			return true
		}
		return false
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if importable(path) {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// sopDocument is one parsed import file: the frontmatter attribution plus the
// prose body.
type sopDocument struct {
	Title          string
	Author         string
	Tags           []string
	Recommendation string
	SourceSystem   string
	SourceURL      string
	SourceVersion  string
	Body           string
}

// sopFrontmatter is the YAML block an import file may open with.
type sopFrontmatter struct {
	Title          string   `yaml:"title"`
	Author         string   `yaml:"author"`
	Tags           []string `yaml:"tags"`
	Recommendation string   `yaml:"recommendation"`
	Source         struct {
		System  string `yaml:"system"`
		URL     string `yaml:"url"`
		Version string `yaml:"version"`
	} `yaml:"source"`
}

// parseSOPDocument reads one markdown/text file: optional `---` YAML
// frontmatter, then prose. Fallbacks keep plain files importable: the title
// comes from the first `# ` heading or the filename, and the source URL —
// the re-import lineage key — defaults to file:<path>.
func parseSOPDocument(path string) (sopDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sopDocument{}, err
	}
	fm, body, err := splitFrontmatter(raw)
	if err != nil {
		return sopDocument{}, err
	}
	doc := sopDocument{
		Title:          fm.Title,
		Author:         fm.Author,
		Tags:           fm.Tags,
		Recommendation: fm.Recommendation,
		SourceSystem:   fm.Source.System,
		SourceURL:      fm.Source.URL,
		SourceVersion:  fm.Source.Version,
		Body:           strings.TrimSpace(body),
	}
	if doc.Body == "" {
		return sopDocument{}, fmt.Errorf("empty body")
	}
	if doc.Title == "" {
		doc.Title = headingOrStem(doc.Body, path)
	}
	if doc.SourceURL == "" {
		doc.SourceSystem = "file"
		doc.SourceURL = "file:" + filepath.ToSlash(filepath.Clean(path))
	}
	return doc, nil
}

// splitFrontmatter separates an optional leading `---` YAML block from the
// prose. No frontmatter is fine — the whole content is body.
func splitFrontmatter(raw []byte) (sopFrontmatter, string, error) {
	var fm sopFrontmatter
	content := strings.ReplaceAll(string(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))), "\r\n", "\n")
	if !strings.HasPrefix(content, "---\n") {
		return fm, content, nil
	}
	rest := content[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		if trimmed, ok := strings.CutSuffix(rest, "\n---"); ok {
			end = len(trimmed)
			rest = trimmed + "\n---\n"
		} else {
			return fm, "", fmt.Errorf("unterminated frontmatter (opening --- without closing ---)")
		}
	}
	if err := yaml.Unmarshal([]byte(rest[:end]), &fm); err != nil {
		return fm, "", fmt.Errorf("frontmatter: %w", err)
	}
	return fm, rest[end+len("\n---\n"):], nil
}

// headingOrStem derives a title from the first `# ` heading, else the
// filename stem.
func headingOrStem(body, path string) string {
	for _, line := range strings.Split(body, "\n") {
		if h, ok := strings.CutPrefix(strings.TrimSpace(line), "# "); ok && strings.TrimSpace(h) != "" {
			return strings.TrimSpace(h)
		}
	}
	stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return strings.ReplaceAll(stem, "-", " ")
}

// postSOPImport submits one document to POST /api/sops/import.
func postSOPImport(ctx context.Context, cred *agent.Credential, backendURL string, doc sopDocument) (string, error) {
	payload := map[string]any{
		"title": doc.Title, "body": doc.Body, "tags": doc.Tags,
		"recommendation": doc.Recommendation,
		"author":         doc.Author,
		"source": map[string]string{
			"system": doc.SourceSystem, "url": doc.SourceURL, "version": doc.SourceVersion,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	token, err := cred.Token(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL+"/api/sops/import", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read-side close
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal(body, &out)
	if out.Outcome == "" {
		out.Outcome = "ok"
	}
	return out.Outcome, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
