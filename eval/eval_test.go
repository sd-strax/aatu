package eval

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEvalRun is the live harness run (10 §5): the real model, the real loop,
// the real backend — costs real tokens and needs the local stack running with
// the lateral-movement scenario wired. It is env-gated and never part of
// -short/make ci (10 §1.5); invoke via `make eval`.
func TestEvalRun(t *testing.T) {
	if os.Getenv("RECKON_EVAL") != "1" {
		t.Skip("eval run disabled; set RECKON_EVAL=1 (use `make eval`)")
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Skip("ANTHROPIC_API_KEY not set (the loop is BYOK)")
	}
	if testing.Short() {
		t.Skip("eval run never executes under -short")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	scenario := filepath.Join("scenarios", "lateral-movement.yaml")
	report, err := Run(ctx, RunConfig{
		ScenarioPath: scenario,
		Log:          t.Logf,
	})
	if err != nil {
		t.Fatalf("eval run: %v", err)
	}

	// The compact human summary (10 §4.3) — the matrix the reviewer reads.
	fmt.Println(report.Summary())

	// Regression check against the committed baseline for this scenario+model
	// (10 §4.4). No baseline (first run) is not a failure — the accepted run's
	// summary gets committed to eval/baselines/ by review.
	baselinePath := BaselinePath("baselines", report.Attribution.ScenarioID, report.Attribution.Model)
	base, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if base == nil {
		t.Logf("no committed baseline at %s — first run for this scenario+model", baselinePath)
	}
	for _, reg := range report.Regressions(base) {
		t.Errorf("regression vs baseline: %s", reg)
	}

	if n := report.MustFailures(); n > 0 {
		t.Errorf("%d MUST assertion(s) failed — see the summary above and the artifact dir", n)
	}

	// A run that did not complete all N trials (model error, credit exhaustion)
	// is not a green run: its verdicts are graded over fewer trials, so a pass
	// is not the all-N guarantee (10 §4.2). Surface it as a failure rather than
	// a misleading PASS — and it must not be accepted as a baseline (accept.go
	// refuses it too).
	if n := len(report.TrialErrors); n > 0 {
		t.Errorf("%d of %d trials did not complete — run is truncated, not acceptable (see trial errors above)",
			n, report.Attribution.Trials)
	}
}

// TestAcceptBaseline commits a completed run's report as the per-model baseline
// (10 §4.4). Token-free — it reads an existing report.json (RECKON_EVAL_REPORT,
// else the latest run under artifacts/), never the model. Gated so it never
// runs in the normal suite; invoke via `make eval-accept`. Refuses a run with
// MUST failures or aborted trials unless RECKON_EVAL_FORCE=1.
func TestAcceptBaseline(t *testing.T) {
	if os.Getenv("RECKON_EVAL_ACCEPT") != "1" {
		t.Skip("baseline accept disabled; set RECKON_EVAL_ACCEPT=1 (use `make eval-accept`)")
	}
	reportPath := os.Getenv("RECKON_EVAL_REPORT")
	if reportPath == "" {
		p, err := LatestReport("artifacts")
		if err != nil {
			t.Fatalf("find latest report: %v", err)
		}
		reportPath = p
	}
	force := os.Getenv("RECKON_EVAL_FORCE") == "1"
	path, err := AcceptBaseline(reportPath, "baselines", force)
	if err != nil {
		t.Fatalf("accept baseline: %v", err)
	}
	fmt.Printf("accepted %s\n  as baseline %s\n  (commit it alongside the prompt change — 10 §4.4)\n", reportPath, path)
}

// TestRegradeRun re-grades the latest run's committed trial records with the
// current grader catalogue and rewrites its report.json (Regrade). Token-free —
// graders are deterministic over the recorded trials, so a grader fix never
// requires re-spending a model run. Gated so it never runs in the normal
// suite; invoke via `make eval-regrade`. Runs the same post-run checks as
// TestEvalRun (regression vs baseline, MUST failures, truncation) so a
// regraded run answers the same question a live run does.
func TestRegradeRun(t *testing.T) {
	if os.Getenv("RECKON_EVAL_REGRADE") != "1" {
		t.Skip("regrade disabled; set RECKON_EVAL_REGRADE=1 (use `make eval-regrade`)")
	}
	runDir := os.Getenv("RECKON_EVAL_RUN")
	if runDir == "" {
		d, err := LatestRunDir("artifacts")
		if err != nil {
			t.Fatalf("find latest run: %v", err)
		}
		runDir = d
	}
	report, err := Regrade(runDir, filepath.Join("scenarios", "lateral-movement.yaml"))
	if err != nil {
		t.Fatalf("regrade: %v", err)
	}
	fmt.Printf("regraded %s with catalogue %s\n", runDir, report.Attribution.CatalogueVersion)
	fmt.Println(report.Summary())

	baselinePath := BaselinePath("baselines", report.Attribution.ScenarioID, report.Attribution.Model)
	base, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if base == nil {
		t.Logf("no committed baseline at %s — first run for this scenario+model", baselinePath)
	}
	for _, reg := range report.Regressions(base) {
		t.Errorf("regression vs baseline: %s", reg)
	}
	if n := report.MustFailures(); n > 0 {
		t.Errorf("%d MUST assertion(s) failed — see the summary above and the artifact dir", n)
	}
	if n := len(report.TrialErrors); n > 0 {
		t.Errorf("%d of %d trials did not complete — run is truncated, not acceptable",
			n, report.Attribution.Trials)
	}
}
