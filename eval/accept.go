package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BaselinePath is where an accepted run's summary is committed for a
// (scenario, model) pair (10 §4.4). Baselines are per-model — the supported
// model set is baseline-defined — so the model id is part of the filename.
func BaselinePath(baselineDir, scenario, model string) string {
	return filepath.Join(baselineDir, scenario+"--"+model+".json")
}

// LatestReport returns the newest report.json under artifactDir (see
// LatestRunDir for the ordering contract).
func LatestReport(artifactDir string) (string, error) {
	dir, err := LatestRunDir(artifactDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "report.json"), nil
}

// AcceptBaseline reduces a run's report to its committable summary (scores, not
// transcripts — 10 §4.3) and writes it to the per-model baseline path, so the
// diff travels with the prompt change (10 §4.4). It is token-free: it reads a
// report the run already wrote, never the model.
//
// It refuses two kinds of run unless force is set — a baseline is an ACCEPTED
// run, and both would make it a meaningless bar:
//
//   - MUST failures: the regression rule is vacuous against a bar that itself
//     fails a correctness/honesty assertion.
//   - Incomplete runs (any trial aborted — model error, credit exhaustion): the
//     verdicts are graded over fewer than N trials, so the bar is thin (a MUST
//     "exercised once" is not the all-N guarantee 10 §4.2 promises) and SHOULD
//     rates carry a different denominator. A truncated run is an infrastructure
//     failure, not an acceptable baseline.
//
// SHOULD failures on a COMPLETE run are fine to bake (the baseline records the
// rate for future comparison). Returns the baseline path written.
func AcceptBaseline(reportPath, baselineDir string, force bool) (string, error) {
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return "", fmt.Errorf("eval: read report: %w", err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return "", fmt.Errorf("eval: parse report %s: %w", reportPath, err)
	}
	if rep.Attribution.ScenarioID == "" || rep.Attribution.Model == "" {
		return "", fmt.Errorf("eval: report %s has no scenario/model attribution", reportPath)
	}
	if n := len(rep.TrialErrors); n > 0 && !force {
		return "", fmt.Errorf("eval: report has %d aborted trial(s); refusing to accept a truncated run "+
			"as a baseline (re-run a clean N=%d, or set RECKON_EVAL_FORCE=1 to override):\n  %s",
			n, rep.Attribution.Trials, strings.Join(rep.TrialErrors, "\n  "))
	}
	if n := rep.MustFailures(); n > 0 && !force {
		return "", fmt.Errorf("eval: report has %d MUST failure(s); refusing to accept as a baseline "+
			"(fix the defect, or set RECKON_EVAL_FORCE=1 to override)", n)
	}
	blob, err := json.MarshalIndent(rep.ToBaseline(), "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(baselineDir, 0o750); err != nil {
		return "", fmt.Errorf("eval: create baseline dir: %w", err)
	}
	path := BaselinePath(baselineDir, rep.Attribution.ScenarioID, rep.Attribution.Model)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return "", fmt.Errorf("eval: write baseline: %w", err)
	}
	return path, nil
}
