package eval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
)

// RunConfig assembles one eval run (10 §2): one scenario, one model, N trials
// against the RUNNING local stack (`reckon start` with the scenario's
// capability/action config). The harness does not boot the stack — it drives
// the same backend an analyst would.
type RunConfig struct {
	ScenarioPath string
	// Model overrides the provider model; empty = RECKON_MODEL or the default.
	Model string
	// ArtifactDir receives the report + per-trial records (transcripts included;
	// local artifacts, never committed — 10 §4.3). Empty = eval/artifacts/<run>.
	ArtifactDir string
	// Log receives progress lines; nil = silent.
	Log func(format string, args ...any)
}

// Run executes the scenario end to end and returns the graded report. The
// report is also written to the artifact dir alongside the per-trial records.
func Run(ctx context.Context, rc RunConfig) (*Report, error) {
	logf := rc.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}

	s, err := LoadScenario(rc.ScenarioPath)
	if err != nil {
		return nil, err
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("eval: ANTHROPIC_API_KEY is not set (the loop is BYOK)")
	}
	model := rc.Model
	if model == "" {
		model = envOr("RECKON_MODEL", agent.DefaultAnthropicModel)
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("eval: load config: %w", err)
	}
	issuer := fmt.Sprintf("http://localhost:%d/realms/%s", cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm)
	backendURL := fmt.Sprintf("http://localhost:%d", cfg.Backend.HTTPPort)

	user := envOr("RECKON_USER", branding.CLI+"-admin")
	pass := envOr("RECKON_PASSWORD", branding.CLI)
	humanCred, err := agent.NewCredential(ctx, issuer, branding.CLI, user, pass)
	if err != nil {
		return nil, fmt.Errorf("eval: login (human client): %w", err)
	}
	agentCred, err := agent.NewCredential(ctx, issuer, branding.CLI+"-agent", user, pass)
	if err != nil {
		return nil, fmt.Errorf("eval: login (agent client): %w", err)
	}
	client := agent.NewClient(backendURL, agentCred, humanCred)

	// The served action vocabulary: H3's ground truth and part of the run's
	// attribution. An error means the action layer is off — recorded as such.
	var catalog []string
	catalogHash := "unavailable"
	if actionTypes, err := client.ListActionTypes(ctx); err == nil {
		for _, a := range actionTypes {
			catalog = append(catalog, a.Descriptor.ActionType)
		}
		if raw, err := json.Marshal(actionTypes); err == nil {
			sum := sha256.Sum256(raw)
			catalogHash = hex.EncodeToString(sum[:])
		}
	}

	logf("eval: scenario %s — %d turns × %d trials on %s (costs real tokens)",
		s.ID, len(s.Turns), s.Trials, model)

	artifactDir := rc.ArtifactDir
	if artifactDir == "" {
		artifactDir = filepath.Join("artifacts", fmt.Sprintf("%s-%s", s.ID, time.Now().Format("20060102-150405")))
	}
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		return nil, fmt.Errorf("eval: create artifact dir: %w", err)
	}

	var (
		trials      []*TrialRecord
		trialErrors []string
		promptHash  string
	)
	for n := 1; n <= s.Trials; n++ {
		logf("eval: trial %d/%d", n, s.Trials)
		tr, sysPrompt, err := runTrial(ctx, client, backendURL, humanCred, s, model, apiKey, n, logf)
		if err != nil {
			trialErrors = append(trialErrors, fmt.Sprintf("trial %d: %v", n, err))
			logf("eval: trial %d aborted: %v", n, err)
		}
		if promptHash == "" && sysPrompt != "" {
			// Prompt-version identifier (10 §1.4): hash of the first trial's
			// assembled system prompt. v0 caveat: assembly embeds investigation
			// context, so this attributes the prompt AS RUN, not the base text —
			// the product stamping a base-prompt version supersedes this (09 §4.2).
			sum := sha256.Sum256([]byte(sysPrompt))
			promptHash = hex.EncodeToString(sum[:])
		}
		if tr != nil {
			tr.ActionCatalog = catalog
			trials = append(trials, tr)
			if raw, err := json.MarshalIndent(tr, "", "  "); err == nil {
				_ = os.WriteFile(filepath.Join(artifactDir, fmt.Sprintf("trial-%d.json", n)), raw, 0o600)
			}
		}
	}
	if len(trials) == 0 {
		return nil, fmt.Errorf("eval: no trial completed: %v", trialErrors)
	}

	report := &Report{
		Attribution: Attribution{
			PromptVersion:     promptHash,
			Model:             model,
			ActionCatalogHash: catalogHash,
			ScenarioID:        s.ID,
			DriverHash:        s.Hash,
			CatalogueVersion:  CatalogueVersion,
			Trials:            s.Trials,
		},
		Results:     Grade(s, trials),
		TrialErrors: trialErrors,
	}
	if raw, err := json.MarshalIndent(report, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(artifactDir, "report.json"), raw, 0o600)
	}
	logf("eval: artifacts in %s", artifactDir)
	return report, nil
}

// runTrial creates + activates a fresh investigation, then drives the shipped
// Session through the script. Returns the trial record (possibly partial, with
// Aborted set) and the assembled system prompt for attribution.
func runTrial(ctx context.Context, client *agent.Client, backendURL string, human agent.TokenSource,
	s *Scenario, model, apiKey string, trial int, logf func(string, ...any)) (*TrialRecord, string, error) {
	invID, err := createActiveInvestigation(ctx, backendURL, human,
		fmt.Sprintf("eval: %s — trial %d", s.ID, trial))
	if err != nil {
		return nil, "", err
	}

	session, err := agent.NewSession(ctx, agent.Config{
		Backend: client,
		LLM: &agent.Anthropic{APIKey: apiKey, Model: model, OnRetry: func(attempt int, wait time.Duration, err error) {
			logf("eval: trial %d — provider backpressure (attempt %d), retrying in %s: %v", trial, attempt, wait.Round(time.Second), err)
		}},
		InvestigationID: invID,
	})
	if err != nil {
		return nil, "", fmt.Errorf("assemble session: %w", err)
	}

	tr := &TrialRecord{Trial: trial, InvestigationID: invID}
	for i, spec := range s.Turns {
		res, err := session.Turn(ctx, spec.User)
		rec := TurnRecord{Index: i, UserMsg: spec.User}
		if res != nil {
			rec.Text = res.Text
			rec.Transcript = res.Transcript
			rec.InterpretationID = res.InterpretationID
			rec.ToolRounds = res.ToolRounds
			for _, tc := range res.ToolCalls {
				rec.ToolCalls = append(rec.ToolCalls, ToolCall{ToolName: tc.ToolName, Args: string(tc.Args)})
			}
		}
		if err != nil {
			// The turn failed (model call or commit) — the record is not the
			// committed truth, so the trial stops here rather than grading
			// unpersisted output (10 §1.1).
			rec.Err = err.Error()
			tr.Turns = append(tr.Turns, rec)
			tr.Aborted = true
			return tr, session.System(), fmt.Errorf("turn %d: %w", i, err)
		}
		tr.Turns = append(tr.Turns, rec)
		logf("eval: trial %d turn %d/%d — %d tool rounds", trial, i+1, len(s.Turns), res.ToolRounds)
	}
	return tr, session.System(), nil
}

// createActiveInvestigation provisions one fresh investigation per trial —
// trials must not share reasoning state — via the product API on the human
// token (create + activate are the analyst's acts).
func createActiveInvestigation(ctx context.Context, backendURL string, human agent.TokenSource, title string) (string, error) {
	var created struct {
		AggregateID string `json:"aggregate_id"`
	}
	if err := postJSON(ctx, human, backendURL+"/api/investigations",
		map[string]any{"title": title}, &created); err != nil {
		return "", fmt.Errorf("create investigation: %w", err)
	}
	if err := postJSON(ctx, human, backendURL+"/api/investigations/"+created.AggregateID+"/lifecycle",
		map[string]any{"transition": "activate"}, nil); err != nil {
		return "", fmt.Errorf("activate investigation: %w", err)
	}
	return created.AggregateID, nil
}

// postJSON is the harness's minimal authenticated POST — for the two
// investigation-provisioning calls the agent Client deliberately does not
// carry (they are surface acts, not loop acts).
func postJSON(ctx context.Context, src agent.TokenSource, url string, in, out any) error {
	token, err := src.Token(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: %d %s", url, resp.StatusCode, string(raw))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
