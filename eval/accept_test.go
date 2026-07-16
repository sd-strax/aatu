package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeReport(t *testing.T, dir string, rep Report) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "report.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func cleanReport() Report {
	return Report{
		Attribution: Attribution{ScenarioID: "s", Model: "m", CatalogueVersion: CatalogueVersion, Trials: 3},
		Results: []AssertionResult{
			{ID: "H3", Severity: Must, Scope: ScopeTrial, Result: Pass, Passed: 3, Exercised: 3},
			{ID: "O1", Severity: Should, Scope: ScopeTrial, Result: Pass, Passed: 3, Exercised: 3},
		},
	}
}

// TestAcceptBaseline_WritesCleanRun: a MUST-passing report reduces to a
// per-model baseline summary that round-trips through LoadBaseline.
func TestAcceptBaseline_WritesCleanRun(t *testing.T) {
	dir := t.TempDir()
	reportPath := writeReport(t, filepath.Join(dir, "run1"), cleanReport())
	baselineDir := filepath.Join(dir, "baselines")

	path, err := AcceptBaseline(reportPath, baselineDir, false)
	if err != nil {
		t.Fatalf("AcceptBaseline: %v", err)
	}
	if want := BaselinePath(baselineDir, "s", "m"); path != want {
		t.Errorf("baseline path = %s; want %s", path, want)
	}
	base, err := LoadBaseline(path)
	if err != nil || base == nil {
		t.Fatalf("LoadBaseline: %v (base=%v)", err, base)
	}
	if base.Attribution.Model != "m" {
		t.Errorf("baseline attribution lost: %+v", base.Attribution)
	}
	if r, ok := base.Results["H3"]; !ok || r.Result != Pass {
		t.Errorf("H3 not recorded in baseline: %+v", base.Results)
	}
}

// TestAcceptBaseline_RefusesMustFailure: a run with a MUST failure is not an
// acceptable baseline unless forced.
func TestAcceptBaseline_RefusesMustFailure(t *testing.T) {
	dir := t.TempDir()
	rep := cleanReport()
	rep.Results = append(rep.Results, AssertionResult{
		ID: "H4", Severity: Must, Scope: ScopeTurn, Turn: 4, Result: Fail, Passed: 1, Failed: 2, Exercised: 3,
	})
	reportPath := writeReport(t, filepath.Join(dir, "run1"), rep)
	baselineDir := filepath.Join(dir, "baselines")

	_, err := AcceptBaseline(reportPath, baselineDir, false)
	if err == nil || !strings.Contains(err.Error(), "MUST failure") {
		t.Fatalf("err = %v; want refusal on MUST failure", err)
	}
	if _, statErr := os.Stat(BaselinePath(baselineDir, "s", "m")); statErr == nil {
		t.Error("baseline written despite MUST failure")
	}

	// Force overrides the guard.
	if _, err := AcceptBaseline(reportPath, baselineDir, true); err != nil {
		t.Fatalf("forced accept: %v", err)
	}
	if _, statErr := os.Stat(BaselinePath(baselineDir, "s", "m")); statErr != nil {
		t.Errorf("forced accept did not write the baseline: %v", statErr)
	}
}

// TestLatestReport: the newest timestamped run directory wins.
func TestLatestReport(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"s-20260716-100000", "s-20260716-235959", "s-20260716-120000"} {
		writeReport(t, filepath.Join(dir, name), cleanReport())
	}
	got, err := LatestReport(dir)
	if err != nil {
		t.Fatalf("LatestReport: %v", err)
	}
	if want := filepath.Join(dir, "s-20260716-235959", "report.json"); got != want {
		t.Errorf("latest = %s; want %s", got, want)
	}

	if _, err := LatestReport(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("expected an error for a missing artifact dir")
	}
}
