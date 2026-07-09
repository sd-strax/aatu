package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// fixtureOperation is the single operation fixture bindings name; the verb being
// replayed travels in params under ParamVerb.
const fixtureOperation = "replay"

// ParamVerb is the reserved params key carrying the verb name into an adapter.
// The resolver populates it (the spec exposes ${verb} as a template root, §3.3);
// the fixture adapter matches on it against each fixture's matches.verb.
const ParamVerb = "verb"

// fixtureFile is the on-disk fixture format (§9.1): OCSF-shaped events with the
// binding metadata needed to replay them.
type fixtureFile struct {
	FixtureMeta struct {
		Scenario string `json:"scenario"`
		Matches  struct {
			Verb   string         `json:"verb"`
			Params map[string]any `json:"params"`
		} `json:"matches"`
		DelayMS int `json:"delay_ms"`
	} `json:"fixture_meta"`
	OCSF map[string]any `json:"ocsf"`
}

// FixtureAdapter replays recorded OCSF events from fixtures/<scenario>/*.json.
// It is a regular Adapter with Class() == ClassFixture (§9.2); the resolver and
// normalizer treat it like any other. It loads its scenario lazily on first use
// and caches it, so it is safe for concurrent Invoke.
type FixtureAdapter struct {
	root     string // fixtures root directory
	scenario string // active scenario subdirectory

	// applyDelays honors each fixture's delay_ms to mimic real latency for UX
	// testing. Tests set it false to run instantly.
	applyDelays bool

	mu       sync.Mutex
	loaded   bool
	fixtures []fixtureFile
}

// NewFixtureAdapter constructs a fixture adapter for the given scenario under
// root (e.g. NewFixtureAdapter("fixtures", "lateral-movement-via-rdp")).
func NewFixtureAdapter(root, scenario string) *FixtureAdapter {
	return &FixtureAdapter{root: root, scenario: scenario, applyDelays: true}
}

// SetApplyDelays toggles honoring fixture delay_ms (default true). Tests disable
// it to avoid sleeping.
func (a *FixtureAdapter) SetApplyDelays(v bool) { a.applyDelays = v }

// Name returns "fixture".
func (a *FixtureAdapter) Name() string { return "fixture" }

// Class returns ClassFixture.
func (a *FixtureAdapter) Class() AdapterClass { return ClassFixture }

// SupportedOperations returns the single replay operation.
func (a *FixtureAdapter) SupportedOperations() []string { return []string{fixtureOperation} }

// sourceTool is the label stamped on replayed events, e.g.
// "fixture:lateral-movement-via-rdp".
func (a *FixtureAdapter) sourceTool() string { return "fixture:" + a.scenario }

// load reads and parses every fixture JSON in the scenario directory. Success
// is cached; a failure is NOT — the next call re-tests, per the §6.2 UNHEALTHY
// semantic ("unusable until re-tested"). Each attempt parses into a fresh slice
// so a retry can never double-append. Sidecar files (asset-criticality.json)
// and raw_response fixtures are skipped.
func (a *FixtureAdapter) load() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded {
		return nil
	}

	dir := filepath.Join(a.root, a.scenario)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read scenario dir %s: %w", dir, err)
	}

	var fixtures []fixtureFile
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if name == "asset-criticality.json" || strings.HasPrefix(name, "raw_response") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read fixture %s: %w", name, err)
		}
		var f fixtureFile
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("parse fixture %s: %w", name, err)
		}
		fixtures = append(fixtures, f)
	}
	// Stable order so multi-event results are deterministic.
	sort.SliceStable(fixtures, func(i, j int) bool {
		return fixtureOrder(fixtures[i]) < fixtureOrder(fixtures[j])
	})

	a.fixtures = fixtures
	a.loaded = true
	return nil
}

// fixtureOrder keys fixtures by event time then verb for a stable, meaningful
// ordering (chronological within a verb).
func fixtureOrder(f fixtureFile) string {
	t, _ := f.OCSF["time"].(string)
	return t + "|" + f.FixtureMeta.Matches.Verb
}

// Invoke replays the fixtures whose matches block satisfies the incoming verb
// and params, honoring each fixture's delay_ms. An unknown operation or a
// missing scenario is a classified AdapterError.
func (a *FixtureAdapter) Invoke(ctx context.Context, operation string, params map[string]any) (AdapterResponse, error) {
	if operation != fixtureOperation {
		return AdapterResponse{}, adapterErrorf(ErrFallthrough, "fixture adapter: unsupported operation %q", operation)
	}
	if err := a.load(); err != nil {
		return AdapterResponse{}, adapterErrorf(ErrUnhealthy, "fixture adapter: %v", err)
	}

	verb, _ := params[ParamVerb].(string)

	var events []OcsfPayload
	for _, f := range a.fixtures {
		if !fixtureMatches(f, verb, params) {
			continue
		}
		if a.applyDelays && f.FixtureMeta.DelayMS > 0 {
			select {
			case <-ctx.Done():
				return AdapterResponse{}, adapterErrorf(ErrRetry, "fixture adapter: %v", ctx.Err())
			case <-time.After(time.Duration(f.FixtureMeta.DelayMS) * time.Millisecond):
			}
		}
		events = append(events, toOcsfPayload(f.OCSF))
	}
	return AdapterResponse{SourceTool: a.sourceTool(), Events: events}, nil
}

// Health reports healthy once the scenario has loaded without error.
func (a *FixtureAdapter) Health() HealthStatus {
	if err := a.load(); err != nil {
		return HealthStatus{Healthy: false, Message: err.Error()}
	}
	return HealthStatus{
		Healthy: true,
		Message: fmt.Sprintf("scenario %q, %d fixtures", a.scenario, len(a.fixtures)),
	}
}

// fixtureMatches reports whether a fixture applies to the incoming (verb,
// params): the verb must equal matches.verb, and every matches.param must equal
// the value at its dotted path in params ("*" matches anything).
func fixtureMatches(f fixtureFile, verb string, params map[string]any) bool {
	if f.FixtureMeta.Matches.Verb != "" && f.FixtureMeta.Matches.Verb != verb {
		return false
	}
	for path, want := range f.FixtureMeta.Matches.Params {
		if s, ok := want.(string); ok && s == "*" {
			continue
		}
		got, ok := lookupPath(params, path)
		if !ok || !valuesEqual(got, want) {
			return false
		}
	}
	return true
}

// lookupPath resolves a dotted path ("target.hostname") into a nested params
// map, falling back to a direct flat key of the same name.
func lookupPath(params map[string]any, path string) (any, bool) {
	if v, ok := params[path]; ok {
		return v, true
	}
	segs := strings.Split(path, ".")
	var cur any = params
	for _, s := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[s]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// valuesEqual compares a matcher value against an incoming value, tolerating the
// JSON number/string ambiguity by comparing canonical string forms.
func valuesEqual(got, want any) bool {
	return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
}

// toOcsfPayload extracts the OCSF header fields (class_uid, class_name, time)
// from a raw OCSF map and wraps the whole map as an OcsfPayload.
func toOcsfPayload(ocsf map[string]any) OcsfPayload {
	return OcsfPayload{
		ClassUID:  toInt(ocsf["class_uid"]),
		ClassName: toString(ocsf["class_name"]),
		Time:      toTime(ocsf["time"]),
		Raw:       ocsf,
	}
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64: // JSON numbers decode as float64
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

// toTime parses an OCSF time value, accepting RFC3339 strings and epoch
// milliseconds (OCSF's numeric time form). Returns the zero time on failure.
func toTime(v any) time.Time {
	switch t := v.(type) {
	case string:
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed.UTC()
		}
	case float64:
		return time.UnixMilli(int64(t)).UTC()
	}
	return time.Time{}
}
