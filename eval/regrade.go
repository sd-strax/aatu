package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// LatestRunDir returns the newest run directory under artifactDir. Runs are
// written to timestamped directories (`<scenario>-<YYYYMMDD-HHMMSS>`), so
// lexical order on the directory name is chronological.
func LatestRunDir(artifactDir string) (string, error) {
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
	return filepath.Join(artifactDir, dirs[len(dirs)-1]), nil
}

// Regrade re-derives a run's report.json from its committed trial records with
// the CURRENT grader catalogue. Token-free by construction: the graders are
// deterministic over the recorded trials (10 §2 — the committed turn record is
// the graded artifact), so a grader fix does not require re-spending a model
// run; the trials are ground truth and the report is derived state.
//
// Attribution is preserved from the original report — it describes the trials
// (model, prompt hash, action catalog, driver) — except CatalogueVersion, which
// describes the grading and is restamped from the current code.
//
// Two refusals keep a regrade honest:
//
//   - Driver-hash mismatch: if the scenario script changed since the run, the
//     recorded trials were driven by a different script (different turns,
//     different assertion scoping) — grading them with the new script would
//     attribute verdicts to turns that never ran. Re-run instead.
//   - Missing trials: every trial the original report counted as completed must
//     round-trip from disk; a partial regrade would silently change the SHOULD
//     denominator (the same reason accept.go refuses truncated runs).
//
// The rewritten report overwrites report.json in place: grader code is
// version-controlled, so the previous derivation is reproducible at its commit.
func Regrade(runDir, scenarioPath string) (*Report, error) {
	s, err := LoadScenario(scenarioPath)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return nil, fmt.Errorf("eval: read original report: %w", err)
	}
	var orig Report
	if err := json.Unmarshal(raw, &orig); err != nil {
		return nil, fmt.Errorf("eval: parse original report: %w", err)
	}

	if orig.Attribution.ScenarioID != s.ID {
		return nil, fmt.Errorf("eval: run is scenario %q but %s is %q",
			orig.Attribution.ScenarioID, scenarioPath, s.ID)
	}
	if orig.Attribution.DriverHash != s.Hash {
		return nil, fmt.Errorf("eval: driver script changed since the run (recorded %s, current %s) — "+
			"the trials were driven by a different script; re-run instead of regrading",
			short(orig.Attribution.DriverHash), short(s.Hash))
	}

	var trials []*TrialRecord
	for n := 1; ; n++ {
		blob, err := os.ReadFile(filepath.Join(runDir, fmt.Sprintf("trial-%d.json", n)))
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("eval: read trial %d: %w", n, err)
		}
		var tr TrialRecord
		if err := json.Unmarshal(blob, &tr); err != nil {
			return nil, fmt.Errorf("eval: parse trial %d: %w", n, err)
		}
		trials = append(trials, &tr)
	}
	if want := orig.Attribution.Trials - len(orig.TrialErrors); len(trials) != want {
		return nil, fmt.Errorf("eval: run dir has %d trial record(s) but the report counts %d completed — "+
			"refusing a partial regrade (the SHOULD denominator would silently change)", len(trials), want)
	}

	report := &Report{
		Attribution: orig.Attribution,
		Results:     Grade(s, trials),
		TrialErrors: orig.TrialErrors,
		Usage:       orig.Usage,
	}
	report.Attribution.CatalogueVersion = CatalogueVersion

	blob, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), blob, 0o600); err != nil {
		return nil, fmt.Errorf("eval: write regraded report: %w", err)
	}
	return report, nil
}
