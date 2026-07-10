package action

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sd-strax/reckon/capability"
)

// fixtureWriteOperation is the single operation fixture action bindings name.
const fixtureWriteOperation = "dispatch"

// fixtureWriteFile is the on-disk action-fixture format (08 §9): a declared
// outcome plus the binding metadata to match it.
type fixtureWriteFile struct {
	FixtureMeta struct {
		Scenario string `json:"scenario"`
		Matches  struct {
			ActionType string         `json:"action_type"`
			Params     map[string]any `json:"params"`
		} `json:"matches"`
		DelayMS int `json:"delay_ms"`
	} `json:"fixture_meta"`
	Result WriteResult `json:"result"`
}

// FixtureWriteAdapter replays declared WriteResults from
// fixtures/<scenario>/*.action.json — the "fake Tines" that lets v0 exercise
// the full request → authorize → dispatch → result → reversal lifecycle without
// a real tool (08 §9). Fixtures declare SUCCEEDED/PARTIAL/FAILED/TIMEOUT/UNKNOWN
// outcomes to drive the failure and reversal paths.
type FixtureWriteAdapter struct {
	root     string
	scenario string

	applyDelays bool

	mu       sync.Mutex
	loaded   bool
	fixtures []fixtureWriteFile
}

// NewFixtureWriteAdapter constructs a fixture write adapter for a scenario.
func NewFixtureWriteAdapter(root, scenario string) *FixtureWriteAdapter {
	return &FixtureWriteAdapter{root: root, scenario: scenario, applyDelays: true}
}

// SetApplyDelays toggles honoring fixture delay_ms (tests disable it).
func (a *FixtureWriteAdapter) SetApplyDelays(v bool) { a.applyDelays = v }

// Name returns "fixture_write".
func (a *FixtureWriteAdapter) Name() string { return "fixture_write" }

// Class returns the fixture adapter class.
func (a *FixtureWriteAdapter) Class() capability.AdapterClass { return capability.ClassFixture }

// SupportedActionOps returns the single dispatch operation.
func (a *FixtureWriteAdapter) SupportedActionOps() []string { return []string{fixtureWriteOperation} }

// load reads the scenario's *.action.json fixtures once. A failure is not
// cached (re-tested on the next call), mirroring the read fixture adapter.
func (a *FixtureWriteAdapter) load() error {
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
	var fixtures []fixtureWriteFile
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".action.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read fixture %s: %w", name, err)
		}
		var f fixtureWriteFile
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("parse fixture %s: %w", name, err)
		}
		fixtures = append(fixtures, f)
	}
	a.fixtures = fixtures
	a.loaded = true
	return nil
}

// Dispatch matches the incoming action against the loaded fixtures and returns
// the declared WriteResult, stamping a synthetic adapter_request_id. A missing
// scenario is UNHEALTHY; no matching fixture is a FATAL (the scenario is
// incomplete — better to fail loudly than silently succeed).
func (a *FixtureWriteAdapter) Dispatch(ctx context.Context, operation string, params map[string]any, idempotencyKey string) (WriteResult, error) {
	if operation != fixtureWriteOperation {
		return WriteResult{}, writeErrorf(WriteFatal, "fixture write adapter: unsupported operation %q", operation)
	}
	if err := a.load(); err != nil {
		return WriteResult{}, writeErrorf(WriteRetryable, "fixture write adapter: %v", err)
	}

	actionType, _ := params[ParamActionType].(string)
	for _, f := range a.fixtures {
		if !writeFixtureMatches(f, actionType, params) {
			continue
		}
		if a.applyDelays && f.FixtureMeta.DelayMS > 0 {
			select {
			case <-ctx.Done():
				return WriteResult{}, writeErrorf(WriteRetryable, "fixture write adapter: %v", ctx.Err())
			case <-time.After(time.Duration(f.FixtureMeta.DelayMS) * time.Millisecond):
			}
		}
		res := f.Result
		if res.AdapterRequestID == "" {
			res.AdapterRequestID = "fixture:" + idempotencyKey
		}
		if res.AuditDepth == "" {
			res.AuditDepth = AuditFull
		}
		return res, nil
	}
	return WriteResult{}, writeErrorf(WriteFatal, "fixture write adapter: no fixture matches action %q", actionType)
}

// Health reports healthy once the scenario has loaded.
func (a *FixtureWriteAdapter) Health() capability.HealthStatus {
	if err := a.load(); err != nil {
		return capability.HealthStatus{Healthy: false, Message: err.Error()}
	}
	return capability.HealthStatus{
		Healthy: true,
		Message: fmt.Sprintf("scenario %q, %d action fixtures", a.scenario, len(a.fixtures)),
	}
}

// writeFixtureMatches reports whether a fixture applies to the incoming action:
// the action_type must equal matches.action_type, and every matches.param must
// equal the value at its dotted path in params ("*" matches anything).
func writeFixtureMatches(f fixtureWriteFile, actionType string, params map[string]any) bool {
	if f.FixtureMeta.Matches.ActionType != "" && f.FixtureMeta.Matches.ActionType != actionType {
		return false
	}
	for path, want := range f.FixtureMeta.Matches.Params {
		if s, ok := want.(string); ok && s == "*" {
			continue
		}
		got, ok := capability.LookupPath(params, path)
		if !ok || fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			return false
		}
	}
	return true
}
