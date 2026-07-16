package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Scenario is one declarative driver script (10 §2, §5): fixture data is the
// backend's concern (the tenant capability/action config); the scenario owns
// the ordered analyst turns and which assertions grade where. The driver never
// branches on model output — determinism on the input side is what makes N
// trials comparable.
type Scenario struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	// Trials is N (10 §2); defaults to 3.
	Trials int `yaml:"trials"`
	// Assert lists the trial-wide assertion ids graded once per trial.
	Assert []string `yaml:"assert"`
	// Turns is the deterministic analyst script, in order.
	Turns []TurnSpec `yaml:"turns"`

	// Hash is the driver-script content hash (run attribution, 10 §1.4).
	// Computed at load; not part of the file.
	Hash string `yaml:"-"`
}

// TurnSpec is one scripted analyst turn plus its turn-scoped expectations
// (10 §2): assertion ids that grade THIS turn's response, with per-turn grader
// configuration.
type TurnSpec struct {
	User string `yaml:"user"`
	// Assert lists turn-scoped assertion ids graded against this turn.
	Assert []string `yaml:"assert"`
	// MinQuotes configures H2: how many distinct exact values from prior tool
	// results the response must reproduce (default 3).
	MinQuotes int `yaml:"min_quotes"`
	// MaxResponseRunes configures O2's per-turn ceiling; 0 = not graded.
	MaxResponseRunes int `yaml:"max_response_runes"`
	// Anchors configures E2: the response must contain at least one (the
	// fixture events' date, or an explicit historical qualifier).
	Anchors []string `yaml:"anchors"`
}

// LoadScenario reads and validates a driver script. Every referenced assertion
// id must exist in the catalogue and be placed at its declared scope — a typo'd
// or misplaced assertion is a broken safety net and fails loudly at load, not
// silently at grading.
func LoadScenario(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("eval: read scenario: %w", err)
	}
	var s Scenario
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("eval: parse scenario %s: %w", path, err)
	}
	if s.ID == "" {
		return nil, fmt.Errorf("eval: scenario %s: id is required", path)
	}
	if len(s.Turns) == 0 {
		return nil, fmt.Errorf("eval: scenario %s: at least one turn is required", path)
	}
	if s.Trials <= 0 {
		s.Trials = 3
	}
	for _, id := range s.Assert {
		a, ok := Catalogue[id]
		if !ok {
			return nil, fmt.Errorf("eval: scenario %s: unknown assertion %q", path, id)
		}
		if a.Scope != ScopeTrial {
			return nil, fmt.Errorf("eval: scenario %s: assertion %s is turn-scoped; place it on a turn", path, id)
		}
	}
	for i, t := range s.Turns {
		if t.User == "" {
			return nil, fmt.Errorf("eval: scenario %s: turn %d has no user text", path, i)
		}
		for _, id := range t.Assert {
			a, ok := Catalogue[id]
			if !ok {
				return nil, fmt.Errorf("eval: scenario %s: turn %d: unknown assertion %q", path, i, id)
			}
			if a.Scope != ScopeTurn {
				return nil, fmt.Errorf("eval: scenario %s: turn %d: assertion %s is trial-wide; place it in the scenario assert list", path, i, id)
			}
		}
	}
	sum := sha256.Sum256(raw)
	s.Hash = hex.EncodeToString(sum[:])
	return &s, nil
}
