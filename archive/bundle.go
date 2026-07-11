// Package archive builds the post-conclusion export bundle (07 §2): a
// self-contained, signed, archive-ready tar.gz of a concluded investigation.
// The bundle is the v0 post-conclusion output — IOC extraction and candidate
// SOPs are v1 (07 §10). Nothing here reaches the database or Temporal; the
// ArchiveInvestigation workflow loads an Investigation and hands it to
// BuildBundle, keeping the format + signing a pure, unit-testable unit.
package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// bundleFormatVersion is the manifest schema version. Bump on any breaking
// change to the bundle layout so an importer can refuse an unknown format.
// 2.0: length-prefixed content-hash framing + signature over the manifest
// bytes (1.0's name\n framing was boundary-malleable and left the manifest
// metadata outside the signed envelope).
const bundleFormatVersion = "2.0"

// Blob is one content-addressed side-store entry (07 §2.1 side-stores/): a
// Layer B transcript or tool-call payload, keyed by its content hash.
type Blob struct {
	Hash  string
	Bytes []byte
}

// HypothesisSummary / ActionSummary are the structured reasoning outputs the
// report renders. The workflow fills them from the *_current projections.
type HypothesisSummary struct {
	ID        string
	Statement string
	Status    string
	Labels    []string
}

type ActionSummary struct {
	ID         string
	ActionType string
	Tier       string
	Status     string
}

// Investigation is everything BuildBundle needs — assembled by the workflow
// from the event store + projections, so the builder never touches the DB.
type Investigation struct {
	GroupingID      string
	Title           string
	Status          string
	Summary         string // conclusion summary
	ReportRef       string
	TenantNamespace string
	ConcludedAt     time.Time

	Events      []json.RawMessage // full event stream, sequence order
	StixObjects []json.RawMessage // interpretation-layer nodes (x-hypothesis/x-prediction/...)
	Hypotheses  []HypothesisSummary
	Actions     []ActionSummary

	// Side stores are included only when the tenant opts in (07 §2.2 optional
	// redaction) — compliance deployments keep prompt content in-prem.
	IncludeSideStores bool
	Transcripts       []Blob
	ToolCalls         []Blob
}

// Manifest is the bundle's manifest.json (07 §2.1). It is the SIGNED statement:
// the detached signature (signatures/bundle.sig) is over the SHA-256 of the
// manifest.json bytes exactly as shipped, and the manifest in turn binds the
// content files via ContentHash + Files. So both the metadata (grouping id,
// tenant namespace, timestamps) and every file byte are inside the signed
// envelope, and verification never needs to re-canonicalize JSON:
//
//  1. sig := signatures/bundle.sig; verify(pubkey, sha256(manifest.json), sig)
//  2. recompute contentHashOf(files listed in Files) == ContentHash
type Manifest struct {
	FormatVersion   string    `json:"format_version"`
	GroupingID      string    `json:"grouping_id"`
	Title           string    `json:"title"`
	Status          string    `json:"status"`
	TenantNamespace string    `json:"tenant_namespace"`
	ConcludedAt     time.Time `json:"concluded_at"`
	GeneratedAt     time.Time `json:"generated_at"`
	Files           []string  `json:"files"` // the content files, sorted
	ContentHash     string    `json:"content_hash"`
	HashAlg         string    `json:"hash_alg"`
}

// Chain is signatures/chain.json (07 §2.1): who signed, when, with what. Sig
// duplicates signatures/bundle.sig for one-file consumption. chain.json is
// deliberately OUTSIDE the signed envelope (it cannot self-authenticate anyway);
// the trust anchor is the out-of-band public key pinned by KeyID.
type Chain struct {
	KeyID    string    `json:"key_id"`
	Alg      string    `json:"alg"`
	SignedAt time.Time `json:"signed_at"`
	Sig      string    `json:"sig"` // hex detached signature over sha256(manifest.json)
}

// Result is a built bundle: the tar.gz bytes, the suggested filename, and the
// content hash (returned so the caller can record it on the archive event).
type Result struct {
	Filename    string
	Bytes       []byte
	ContentHash string
}

// Signer signs a bundle's manifest digest (07 §2.2). Detached, so verification
// is independent of reckon. Injected so the builder stays pure and tests use an
// in-memory key.
type Signer interface {
	KeyID() string
	Alg() string
	Sign(digest []byte) ([]byte, error)
}

// BuildBundle renders, hashes, signs, and packs an investigation into the
// export bundle (07 §2.3 steps 6–8; step 9 — writing to the archive target — is
// the workflow's job). generatedAt is passed in (not read from the clock) so
// the workflow stays deterministic and tests are reproducible. A nil signer
// produces an unsigned bundle (no signatures/ files) — the workflow always
// passes one; unsigned is for callers that sign out of band.
func BuildBundle(inv Investigation, signer Signer, generatedAt time.Time) (Result, error) {
	// The content files, built in a stable order. The manifest is added last,
	// after its ContentHash is computed over these.
	files := map[string][]byte{
		"investigation.report.md": []byte(renderReport(inv)),
		"events.jsonl":            jsonl(inv.Events),
		"stix-bundle.json":        stixBundle(inv.StixObjects),
	}
	if inv.IncludeSideStores {
		for _, b := range inv.Transcripts {
			files["side-stores/transcripts/"+b.Hash+".txt"] = b.Bytes
		}
		for _, b := range inv.ToolCalls {
			files["side-stores/tool-calls/"+b.Hash+".json"] = b.Bytes
		}
	}

	// Content hash over every content file (framed so a rename or a byte flip
	// both change it). Computed before the manifest/signatures are added, so it
	// is not self-referential; those files are content-derived anyway.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	contentHash := contentHashOf(files)
	contentHashHex := hex.EncodeToString(contentHash)

	manifest := Manifest{
		FormatVersion:   bundleFormatVersion,
		GroupingID:      inv.GroupingID,
		Title:           inv.Title,
		Status:          inv.Status,
		TenantNamespace: inv.TenantNamespace,
		ConcludedAt:     inv.ConcludedAt.UTC(),
		GeneratedAt:     generatedAt.UTC(),
		Files:           names,
		ContentHash:     contentHashHex,
		HashAlg:         "sha256",
	}
	manifestBytes := mustJSON(manifest)
	files["manifest.json"] = manifestBytes

	// The signature is over the SHA-256 of the manifest bytes as shipped — so
	// the metadata AND (via ContentHash) every file byte sit inside the signed
	// envelope, and a verifier never re-canonicalizes JSON.
	if signer != nil {
		digest := sha256.Sum256(manifestBytes)
		sig, err := signer.Sign(digest[:])
		if err != nil {
			return Result{}, fmt.Errorf("sign bundle: %w", err)
		}
		files["signatures/bundle.sig"] = []byte(hex.EncodeToString(sig))
		files["signatures/chain.json"] = mustJSON(Chain{
			KeyID:    signer.KeyID(),
			Alg:      signer.Alg(),
			SignedAt: generatedAt.UTC(),
			Sig:      hex.EncodeToString(sig),
		})
	}

	packed, err := packTarGz(files)
	if err != nil {
		return Result{}, err
	}
	// The filename timestamp is the CONCLUSION time, not the build clock: a
	// retried build lands on the SAME path (overwriting an equivalent bundle)
	// instead of accumulating clock-named siblings.
	ts := inv.ConcludedAt
	if ts.IsZero() {
		ts = generatedAt
	}
	return Result{
		Filename:    fmt.Sprintf("investigation-%s-%s.tar.gz", inv.GroupingID, ts.UTC().Format("20060102T150405Z")),
		Bytes:       packed,
		ContentHash: contentHashHex,
	}, nil
}

// contentHashOf hashes a set of files deterministically: sorted by name, each
// contribution framed as len(name) ‖ name ‖ len(body) ‖ body (uint64 big-
// endian). The length prefixes make the encoding injective — no two distinct
// file sets share a digest. (The 1.0 "name\n"+bytes framing was malleable:
// {"a": "x\nb\ny"} and {"a": "x", "b": "y"} concatenated identically, so file
// boundaries could be restructured under a valid signature.)
func contentHashOf(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	var lenBuf [8]byte
	for _, n := range names {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(n)))
		h.Write(lenBuf[:])
		h.Write([]byte(n))
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(files[n])))
		h.Write(lenBuf[:])
		h.Write(files[n])
	}
	return h.Sum(nil)
}

// jsonl joins raw JSON messages one-per-line (events.jsonl, 07 §2.1).
func jsonl(msgs []json.RawMessage) []byte {
	var b bytes.Buffer
	for _, m := range msgs {
		b.Write(bytes.TrimSpace(m))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// stixBundle wraps the interpretation-layer nodes in a STIX 2.1 bundle envelope
// (07 §2.1 stix-bundle.json). v0 emits the stored nodes as-is; edges flattened
// to Relationship objects land with full STIX CRUD in Phase E.
func stixBundle(objects []json.RawMessage) []byte {
	if objects == nil {
		objects = []json.RawMessage{}
	}
	return mustJSON(map[string]any{
		"type":         "bundle",
		"spec_version": "2.1",
		"objects":      objects,
	})
}

// renderReport renders investigation.report.md from the structured summary
// (07 §2.1). Deterministic — no clock, stable ordering.
func renderReport(inv Investigation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Investigation %s\n\n", inv.GroupingID)
	if inv.Title != "" {
		fmt.Fprintf(&b, "**%s**\n\n", inv.Title)
	}
	fmt.Fprintf(&b, "- Status: %s\n", inv.Status)
	if !inv.ConcludedAt.IsZero() {
		fmt.Fprintf(&b, "- Concluded: %s\n", inv.ConcludedAt.UTC().Format(time.RFC3339))
	}
	if inv.ReportRef != "" {
		fmt.Fprintf(&b, "- Report: %s\n", inv.ReportRef)
	}
	b.WriteString("\n")
	if inv.Summary != "" {
		fmt.Fprintf(&b, "## Conclusion\n\n%s\n\n", inv.Summary)
	}
	if len(inv.Hypotheses) > 0 {
		b.WriteString("## Hypotheses\n\n")
		for _, h := range inv.Hypotheses {
			fmt.Fprintf(&b, "- **[%s]** %s (`%s`)", h.Status, h.Statement, h.ID)
			if len(h.Labels) > 0 {
				fmt.Fprintf(&b, " — %s", strings.Join(h.Labels, ", "))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(inv.Actions) > 0 {
		b.WriteString("## Actions\n\n")
		for _, a := range inv.Actions {
			fmt.Fprintf(&b, "- **[%s]** %s (%s) `%s`\n", a.Status, a.ActionType, a.Tier, a.ID)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func packTarGz(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic archive ordering

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		body := files[n]
		if err := tw.WriteHeader(&tar.Header{
			Name: n,
			Mode: 0o644,
			Size: int64(len(body)),
		}); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", n, err)
		}
		if _, err := tw.Write(body); err != nil {
			return nil, fmt.Errorf("tar write %s: %w", n, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// The inputs are plain structs/maps of serializable content; a marshal
		// failure is a programming error, not a runtime condition.
		panic(fmt.Sprintf("archive: marshal: %v", err))
	}
	return b
}
