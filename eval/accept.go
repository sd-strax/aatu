package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// BaselinePath is where an accepted run's summary is committed for a
// (scenario, model) pair (10 §4.4). Baselines are per-model — the supported
// model set is baseline-defined — so the model id is part of the filename.
func BaselinePath(baselineDir, scenario, model string) string {
	return filepath.Join(baselineDir, scenario+"--"+model+".json")
}

// LatestReport returns the newest report.json under artifactDir. Runs are
// written to timestamped directories (`<scenario>-<YYYYMMDD-HHMMSS>`), so
// lexical order on the directory name is chronological.
func LatestReport(artifactDir string) (string, error) {
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return "", fmt.Errorf("eval: read artifact dir %s: %w", artifactDir, err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("eval: no runs under %s", artifactDir)
	}
	sort.Strings(dirs)
	return filepath.Join(artifactDir, dirs[len(dirs)-1], "report.json"), nil
}

// AcceptBaseline reduces a run's report to its committable summary (scores, not
// transcripts — 10 §4.3) and writes it to the per-model baseline path, so the
// diff travels with the prompt change (10 §4.4). It is token-free: it reads a
// report the run already wrote, never the model.
//
// It refuses a report carrying MUST failures unless force is set — a baseline
// is an ACCEPTED run, and the regression rule is meaningless against a bar that
// itself fails a correctness/honesty assertion. SHOULD failures are fine to
// bake (the baseline records the rate for future comparison). Returns the
// baseline path written.
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
