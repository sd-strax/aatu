package action

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/capability"
)

// --- stub write adapter ------------------------------------------------------

type stubWriteAdapter struct {
	name    string
	healthy bool
	result  WriteResult
	err     error
	calls   int
}

func (s *stubWriteAdapter) Name() string                   { return s.name }
func (s *stubWriteAdapter) Class() capability.AdapterClass { return capability.ClassCustom }
func (s *stubWriteAdapter) SupportedActionOps() []string   { return []string{"op"} }
func (s *stubWriteAdapter) Health() capability.HealthStatus {
	return capability.HealthStatus{Healthy: s.healthy}
}
func (s *stubWriteAdapter) Dispatch(_ context.Context, _ string, _ map[string]any, _ string) (WriteResult, error) {
	s.calls++
	return s.result, s.err
}

func okResult() WriteResult {
	return WriteResult{FinalOutcome: OutcomeSucceeded, PerTargetResults: map[string]PerTargetResult{"0": TargetOK}, AuditDepth: AuditFull}
}

func target(id string) aggregate.TargetSpec {
	return aggregate.TargetSpec{EntityRef: "x-host--" + id, ResolvedIdentifier: id}
}

// --- descriptor / list_action_types -----------------------------------------

func TestListActionTypesStatus(t *testing.T) {
	catalog := DefaultActionCatalog()
	r := NewActionResolver(
		map[string][]ActionBinding{
			"host.isolate":    {{ActionType: "host.isolate", Adapter: "edr", Operation: "op", Priority: 100}},
			"account.disable": {{ActionType: "account.disable", Adapter: "down", Operation: "op", Priority: 100}},
		},
		map[string]WriteAdapter{
			"edr":  &stubWriteAdapter{name: "edr", healthy: true},
			"down": &stubWriteAdapter{name: "down", healthy: false},
		},
	)
	byType := map[string]ActionAvailability{}
	for _, s := range r.ListActionTypes(catalog) {
		byType[s.Descriptor.ActionType] = s.Status
	}
	if byType["host.isolate"] != ActionAvailable {
		t.Errorf("host.isolate = %q; want available", byType["host.isolate"])
	}
	if byType["account.disable"] != ActionDegraded {
		t.Errorf("account.disable = %q; want degraded", byType["account.disable"])
	}
	if byType["email.purge"] != ActionUnavailable {
		t.Errorf("email.purge = %q; want unavailable (no binding)", byType["email.purge"])
	}
}

// --- request construction + blast-radius escalator ---------------------------

func TestBuildRequestCommand(t *testing.T) {
	catalog := DefaultActionCatalog()
	now := time.Date(2026, 4, 20, 14, 0, 0, 0, time.UTC)

	cmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType: "host.isolate",
		Targets:    []aggregate.TargetSpec{target("WIN-A")},
		Rationale:  "contain",
	}, now)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cmd.Tier != aggregate.TierT2 {
		t.Errorf("tier = %q; want T2", cmd.Tier)
	}
	if cmd.ActionID == (uuid.UUID{}) {
		t.Error("ActionID not minted")
	}
	if !cmd.ExpiresAt.Equal(now.Add(DefaultRequestTTL)) {
		t.Errorf("expires_at = %v; want now+TTL", cmd.ExpiresAt)
	}
}

func TestBlastRadiusEscalator(t *testing.T) {
	catalog := DefaultActionCatalog()
	now := time.Now()

	many := make([]aggregate.TargetSpec, DefaultBlastRadiusThreshold+1)
	for i := range many {
		many[i] = target("host-" + string(rune('a'+i)))
	}
	cmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType: "host.isolate", // T2 by default
		Targets:    many,
		Rationale:  "mass containment",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Tier != aggregate.TierT3 {
		t.Errorf("11 targets on a T2 action → tier %q; want T3 (blast-radius escalator)", cmd.Tier)
	}

	// An already-irreversible T3 action stays T3 regardless of count.
	if got := EscalateTier(aggregate.TierT3, 1, DefaultBlastRadiusThreshold); got != aggregate.TierT3 {
		t.Errorf("T3 single-target escalated to %q; want T3", got)
	}
	// A T2 under the threshold stays T2.
	if got := EscalateTier(aggregate.TierT2, DefaultBlastRadiusThreshold, DefaultBlastRadiusThreshold); got != aggregate.TierT2 {
		t.Errorf("T2 at threshold escalated to %q; want T2", got)
	}

	// The escalator counts DISTINCT entities (04 §1), not raw list length: the
	// same entity duplicated 11 times is one target, not eleven.
	dupes := make([]aggregate.TargetSpec, DefaultBlastRadiusThreshold+1)
	for i := range dupes {
		dupes[i] = target("same-host")
	}
	cmd, err = BuildRequestCommand(catalog, ActionRequest{
		ActionType: "host.isolate", Targets: dupes, Rationale: "dup",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Tier != aggregate.TierT2 {
		t.Errorf("11 duplicates of one entity escalated to %q; want T2 (1 distinct)", cmd.Tier)
	}
}

func TestBuildRequestCommandRejections(t *testing.T) {
	catalog := DefaultActionCatalog()
	now := time.Now()
	cases := map[string]ActionRequest{
		"unknown type":   {ActionType: "nope", Targets: []aggregate.TargetSpec{target("x")}, Rationale: "r"},
		"no targets":     {ActionType: "host.isolate", Rationale: "r"},
		"no rationale":   {ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("x")}},
		"unresolved tgt": {ActionType: "host.isolate", Targets: []aggregate.TargetSpec{{EntityRef: "x-host--1"}}, Rationale: "r"},
	}
	for name, req := range cases {
		if _, err := BuildRequestCommand(catalog, req, now); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// --- resolver ----------------------------------------------------------------

func TestActionResolverDispatches(t *testing.T) {
	edr := &stubWriteAdapter{name: "edr", healthy: true, result: okResult()}
	r := NewActionResolver(
		map[string][]ActionBinding{"host.isolate": {{
			ActionType: "host.isolate", Adapter: "edr", Operation: "op", Priority: 100,
			Params: map[string]any{"device_id": "${target.resolved_identifier}"},
		}}},
		map[string]WriteAdapter{"edr": edr},
	)
	res, binding, err := r.Resolve(context.Background(), DispatchRequest{
		ActionID: uuid.New(), ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("WIN-A14")},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.FinalOutcome != OutcomeSucceeded || binding.Adapter != "edr" {
		t.Errorf("unexpected result %+v / binding %+v", res, binding)
	}
}

// TestActionResolverNoFallThrough is the write-side invariant: once a binding is
// chosen, a failed dispatch is NOT retried against a lower-priority binding — a
// partially-executed state change must not be re-attempted against another tool.
func TestActionResolverNoFallThrough(t *testing.T) {
	primary := &stubWriteAdapter{name: "primary", healthy: true, err: writeErrorf(WriteFatal, "boom")}
	backup := &stubWriteAdapter{name: "backup", healthy: true, result: okResult()}
	r := NewActionResolver(
		map[string][]ActionBinding{"host.isolate": {
			{ActionType: "host.isolate", Adapter: "primary", Operation: "op", Priority: 100},
			{ActionType: "host.isolate", Adapter: "backup", Operation: "op", Priority: 50},
		}},
		map[string]WriteAdapter{"primary": primary, "backup": backup},
	)
	_, _, err := r.Resolve(context.Background(), DispatchRequest{
		ActionID: uuid.New(), ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("WIN-A")},
	})
	if err == nil {
		t.Fatal("expected the primary dispatch error to propagate")
	}
	if primary.calls != 1 {
		t.Errorf("primary calls = %d; want 1", primary.calls)
	}
	if backup.calls != 0 {
		t.Errorf("backup calls = %d; want 0 (no fall-through after a chosen binding fails)", backup.calls)
	}
}

// A binding whose adapter is absent IS skipped (selection fall-through, distinct
// from dispatch fall-through) — the next applicable binding runs.
func TestActionResolverSkipsAbsentAdapter(t *testing.T) {
	backup := &stubWriteAdapter{name: "backup", healthy: true, result: okResult()}
	r := NewActionResolver(
		map[string][]ActionBinding{"host.isolate": {
			{ActionType: "host.isolate", Adapter: "missing", Operation: "op", Priority: 100},
			{ActionType: "host.isolate", Adapter: "backup", Operation: "op", Priority: 50},
		}},
		map[string]WriteAdapter{"backup": backup},
	)
	_, binding, err := r.Resolve(context.Background(), DispatchRequest{
		ActionID: uuid.New(), ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("WIN-A")},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if binding.Adapter != "backup" || backup.calls != 1 {
		t.Errorf("absent adapter not skipped to backup: binding=%s calls=%d", binding.Adapter, backup.calls)
	}
}

func TestActionResolverNoBinding(t *testing.T) {
	r := NewActionResolver(map[string][]ActionBinding{}, map[string]WriteAdapter{})
	_, _, err := r.Resolve(context.Background(), DispatchRequest{ActionID: uuid.New(), ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("x")}})
	if !errors.Is(err, ErrNoBinding) {
		t.Errorf("err = %v; want ErrNoBinding", err)
	}
}

// --- fixture write adapter ---------------------------------------------------

func writeFixtureAdapter(t *testing.T, files map[string]string) *FixtureWriteAdapter {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "s")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a := NewFixtureWriteAdapter(root, "s")
	a.SetApplyDelays(false)
	return a
}

func TestFixtureWriteAdapterMatch(t *testing.T) {
	a := writeFixtureAdapter(t, map[string]string{
		"isolate.action.json": `{
          "fixture_meta":{"scenario":"s","matches":{"action_type":"host.isolate","params":{"resolved_identifier":"WIN-A14"}},"delay_ms":0},
          "result":{"final_outcome":"SUCCEEDED","per_target_results":{"0":"OK"},"audit_depth":"FULL"}
        }`,
		"purge.action.json": `{
          "fixture_meta":{"scenario":"s","matches":{"action_type":"email.purge","params":{}},"delay_ms":0},
          "result":{"final_outcome":"FAILED","per_target_results":{"0":"FAIL"},"error_class":"FATAL_ERROR"}
        }`,
	})

	res, err := a.Dispatch(context.Background(), "dispatch", map[string]any{
		ParamActionType: "host.isolate", ParamResolvedIdentifier: "WIN-A14",
	}, "key-1")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.FinalOutcome != OutcomeSucceeded || res.AdapterRequestID == "" {
		t.Errorf("unexpected result: %+v", res)
	}

	// A FAILED fixture drives the failure path.
	res, err = a.Dispatch(context.Background(), "dispatch", map[string]any{ParamActionType: "email.purge"}, "key-2")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.FinalOutcome != OutcomeFailed || res.ErrorClass != WriteFatal {
		t.Errorf("failed fixture not surfaced: %+v", res)
	}
}

func TestFixtureWriteAdapterNoMatchIsFatal(t *testing.T) {
	a := writeFixtureAdapter(t, map[string]string{
		"only.action.json": `{"fixture_meta":{"scenario":"s","matches":{"action_type":"host.isolate","params":{}}},"result":{"final_outcome":"SUCCEEDED","audit_depth":"FULL"}}`,
	})
	_, err := a.Dispatch(context.Background(), "dispatch", map[string]any{ParamActionType: "account.disable"}, "k")
	var we *WriteError
	if !errors.As(err, &we) || we.Class != WriteFatal {
		t.Errorf("no-match should be FATAL_ERROR; got %v", err)
	}
}

// --- idempotency -------------------------------------------------------------

func TestIdempotencyKeyDeterministic(t *testing.T) {
	id := uuid.New()
	k1, k2 := IdempotencyKey(id, "WIN-A"), IdempotencyKey(id, "WIN-A")
	if k1 != k2 {
		t.Error("idempotency key not deterministic")
	}
	if IdempotencyKey(id, "WIN-A") == IdempotencyKey(id, "WIN-B") {
		t.Error("different targets should yield different keys")
	}
	if IdempotencyKey(id, "WIN-A") == IdempotencyKey(uuid.New(), "WIN-A") {
		t.Error("different actions should yield different keys")
	}
}
