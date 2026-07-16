package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Attribution is the run's identity block (10 §1.4): without it a report is a
// vibe. PromptVersion is the content hash of the assembled base prompt;
// ActionCatalogHash covers the served action-type vocabulary.
type Attribution struct {
	PromptVersion     string `json:"prompt_version"`
	Model             string `json:"model"`
	ActionCatalogHash string `json:"action_catalog_hash"`
	ScenarioID        string `json:"scenario_id"`
	DriverHash        string `json:"driver_hash"`
	CatalogueVersion  string `json:"catalogue_version"`
	Trials            int    `json:"trials"`
}

// AssertionResult is one assertion's aggregated outcome across N trials
// (10 §4.2): MUST passes only when every exercised trial passes and at least
// one trial exercised it; SHOULD reports a pass rate over exercised trials.
type AssertionResult struct {
	ID        string    `json:"id"`
	Statement string    `json:"statement"`
	Severity  string    `json:"severity"`
	Scope     string    `json:"scope"`
	Turn      int       `json:"turn,omitempty"` // turn index for turn-scoped assertions
	Verdicts  []Verdict `json:"verdicts"`       // one per trial, in trial order
	// Result is the aggregate: PASS/FAIL for MUST; for SHOULD it is PASS when
	// every exercised trial passed (the rate carries the nuance).
	Result    string `json:"result"`
	Passed    int    `json:"passed"`
	Failed    int    `json:"failed"`
	Exercised int    `json:"exercised"`
}

// Key identifies the assertion instance: turn-scoped assertions grade a
// specific turn, so the same id may appear once per turn that declares it.
func (r AssertionResult) Key() string {
	if r.Scope == ScopeTurn {
		return fmt.Sprintf("%s@turn%d", r.ID, r.Turn)
	}
	return r.ID
}

// Report is the one-JSON-document run artifact (10 §4.3).
type Report struct {
	Attribution Attribution       `json:"attribution"`
	Results     []AssertionResult `json:"results"`
	// TrialErrors records trials that aborted before completing the script.
	TrialErrors []string `json:"trial_errors,omitempty"`
}

// Grade evaluates the scenario's assertion placements against the recorded
// trials and aggregates per 10 §4.2. Turn-scoped assertions on turns a trial
// never reached grade NOT_EXERCISED for that trial.
func Grade(s *Scenario, trials []*TrialRecord) []AssertionResult {
	var results []AssertionResult

	for _, id := range s.Assert {
		a := Catalogue[id]
		res := AssertionResult{ID: a.ID, Statement: a.Statement, Severity: a.Severity, Scope: a.Scope}
		for _, tr := range trials {
			res.Verdicts = append(res.Verdicts, a.GradeTrial(tr))
		}
		results = append(results, aggregate(res))
	}

	for turnIdx, spec := range s.Turns {
		for _, id := range spec.Assert {
			a := Catalogue[id]
			res := AssertionResult{ID: a.ID, Statement: a.Statement, Severity: a.Severity, Scope: a.Scope, Turn: turnIdx}
			for _, tr := range trials {
				if turnIdx >= len(tr.Turns) || tr.Turns[turnIdx].Err != "" {
					res.Verdicts = append(res.Verdicts, Verdict{Result: NotExercised, Detail: "turn not reached (trial aborted)"})
					continue
				}
				res.Verdicts = append(res.Verdicts, a.GradeTurn(tr, turnIdx, spec))
			}
			results = append(results, aggregate(res))
		}
	}
	return results
}

// aggregate folds per-trial verdicts into the assertion's result (10 §4.2). A
// fully-unexercised assertion reports NOT_EXERCISED — visible non-coverage,
// never a pass.
func aggregate(res AssertionResult) AssertionResult {
	for _, v := range res.Verdicts {
		switch v.Result {
		case Pass:
			res.Passed++
			res.Exercised++
		case Fail:
			res.Failed++
			res.Exercised++
		}
	}
	switch {
	case res.Exercised == 0:
		res.Result = NotExercised
	case res.Failed > 0:
		res.Result = Fail
	default:
		res.Result = Pass
	}
	return res
}

// MustFailures counts failed MUST assertions — the defect count (10 §4.2).
func (r *Report) MustFailures() int {
	n := 0
	for _, res := range r.Results {
		if res.Severity == Must && res.Result == Fail {
			n++
		}
	}
	return n
}

// Summary renders the compact human matrix printed at the end of `make eval`
// (10 §4.3): one line per assertion instance with per-trial verdict marks.
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "eval run — scenario %s, model %s, %d trials\n",
		r.Attribution.ScenarioID, r.Attribution.Model, r.Attribution.Trials)
	fmt.Fprintf(&b, "prompt %s  catalogue %s\n\n",
		short(r.Attribution.PromptVersion), r.Attribution.CatalogueVersion)
	for _, res := range r.Results {
		marks := make([]string, len(res.Verdicts))
		for i, v := range res.Verdicts {
			switch v.Result {
			case Pass:
				marks[i] = "✓"
			case Fail:
				marks[i] = "✗"
			default:
				marks[i] = "·"
			}
		}
		rate := ""
		if res.Severity == Should && res.Exercised > 0 {
			rate = fmt.Sprintf(" (%d/%d)", res.Passed, res.Exercised)
		}
		fmt.Fprintf(&b, "%-14s %-6s %-13s [%s]%s  %s\n",
			res.Key(), res.Severity, res.Result, strings.Join(marks, " "), rate, res.Statement)
	}
	if n := r.MustFailures(); n > 0 {
		fmt.Fprintf(&b, "\n%d MUST assertion(s) failed — defects.\n", n)
	}
	for _, e := range r.TrialErrors {
		fmt.Fprintf(&b, "trial error: %s\n", e)
	}
	return b.String()
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// --- Baseline comparison (10 §4.4) ------------------------------------------

// BaselineSummary is the committed shape of an accepted run — scores, not
// transcripts — so the diff travels with a prompt change. Keyed per
// (scenario, model): baselines are per-model and the supported-model set is
// baseline-defined (10 §4.4).
type BaselineSummary struct {
	Attribution Attribution        `json:"attribution"`
	Results     map[string]RateRef `json:"results"` // by AssertionResult.Key()
}

// RateRef is one assertion's accepted score.
type RateRef struct {
	Severity  string `json:"severity"`
	Result    string `json:"result"`
	Passed    int    `json:"passed"`
	Exercised int    `json:"exercised"`
}

// ToBaseline reduces a report to its committable summary.
func (r *Report) ToBaseline() BaselineSummary {
	out := BaselineSummary{Attribution: r.Attribution, Results: map[string]RateRef{}}
	for _, res := range r.Results {
		out.Results[res.Key()] = RateRef{
			Severity: res.Severity, Result: res.Result,
			Passed: res.Passed, Exercised: res.Exercised,
		}
	}
	return out
}

// LoadBaseline reads a committed baseline summary; a missing file returns
// (nil, nil) — no baseline means nothing to regress against (first run).
func LoadBaseline(path string) (*BaselineSummary, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("eval: read baseline: %w", err)
	}
	var b BaselineSummary
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("eval: parse baseline %s: %w", path, err)
	}
	return &b, nil
}

// Regressions applies the 10 §4.4 rule against a baseline: a MUST regressing
// PASS→FAIL, or a SHOULD pass rate dropping by more than one trial's worth,
// is a regression. Returns human-readable findings; empty means acceptable.
func (r *Report) Regressions(base *BaselineSummary) []string {
	if base == nil {
		return nil
	}
	var out []string
	for _, res := range r.Results {
		prev, ok := base.Results[res.Key()]
		if !ok {
			continue // new assertion — no baseline to regress against
		}
		switch res.Severity {
		case Must:
			if prev.Result == Pass && res.Result == Fail {
				out = append(out, fmt.Sprintf("%s: MUST regressed PASS -> FAIL", res.Key()))
			}
		case Should:
			if prev.Exercised == 0 || res.Exercised == 0 {
				continue
			}
			prevRate := float64(prev.Passed) / float64(prev.Exercised)
			rate := float64(res.Passed) / float64(res.Exercised)
			tolerance := 1.0 / float64(res.Exercised) // one trial's worth
			if rate < prevRate-tolerance {
				out = append(out, fmt.Sprintf("%s: SHOULD rate dropped %.2f -> %.2f (tolerance %.2f)",
					res.Key(), prevRate, rate, tolerance))
			}
		}
	}
	sort.Strings(out)
	return out
}
