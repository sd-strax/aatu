package action

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestPlannedBinding: the pre-approval preview picks the same binding Resolve
// would — highest priority whose adapter is configured — without dispatching.
func TestPlannedBinding(t *testing.T) {
	r := NewActionResolver(
		map[string][]ActionBinding{
			// The real SoR outranks the demo fixture (mirrors servicenow@200 vs
			// fixture_write@100).
			"ticket.create": {
				{ActionType: "ticket.create", Adapter: "servicenow", Operation: "create_incident", Priority: 200},
				{ActionType: "ticket.create", Adapter: "fixture_write", Operation: "dispatch", Priority: 100},
			},
		},
		map[string]WriteAdapter{
			"servicenow":    &stubWriteAdapter{name: "servicenow", healthy: true},
			"fixture_write": &stubWriteAdapter{name: "fixture_write", healthy: true},
		},
	)

	b, ok := r.PlannedBinding(DispatchRequest{ActionType: "ticket.create", Targets: []aggregate.TargetSpec{target("Service Desk")}})
	if !ok || b.Adapter != "servicenow" {
		t.Fatalf("planned = %q (ok=%v); want servicenow (higher priority)", b.Adapter, ok)
	}

	// With servicenow not configured, the preview falls to the next binding —
	// exactly what dispatch would do (no false promise of a disabled tool).
	r2 := NewActionResolver(
		map[string][]ActionBinding{"ticket.create": {
			{ActionType: "ticket.create", Adapter: "servicenow", Operation: "create_incident", Priority: 200},
			{ActionType: "ticket.create", Adapter: "fixture_write", Operation: "dispatch", Priority: 100},
		}},
		map[string]WriteAdapter{"fixture_write": &stubWriteAdapter{name: "fixture_write", healthy: true}},
	)
	if b, ok := r2.PlannedBinding(DispatchRequest{ActionType: "ticket.create", Targets: []aggregate.TargetSpec{target("Service Desk")}}); !ok || b.Adapter != "fixture_write" {
		t.Errorf("planned with servicenow disabled = %q (ok=%v); want fixture_write", b.Adapter, ok)
	}

	// No binding for the type → no preview.
	if _, ok := r.PlannedBinding(DispatchRequest{ActionType: "email.purge"}); ok {
		t.Error("email.purge has no binding; want ok=false")
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
	// 04 §7.1: the descriptor's reversibility classification is frozen onto the
	// request, so the REVERSED-claim gate reads the value the analyst approved
	// under — a later catalog edit cannot re-classify an in-flight action.
	if cmd.Reversibility != ReversibilityReversible {
		t.Errorf("reversibility = %q; want frozen %q", cmd.Reversibility, ReversibilityReversible)
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
		// Parameter-schema validation (08 §3: Inputs is the schema for
		// request_action.parameters). Both found by the eval harness: the model
		// invented {"title","body"} for ticket.create instead of the declared
		// {summary, description, ...} — undetected until a real binding would
		// template ${parameters.summary} post-approval.
		"undeclared parameter key": {ActionType: "ticket.create",
			Targets:    []aggregate.TargetSpec{target("IT-OPS")},
			Parameters: []byte(`{"title":"t","body":"b"}`), Rationale: "r"},
		"missing required parameter": {ActionType: "ticket.create",
			Targets:    []aggregate.TargetSpec{target("IT-OPS")},
			Parameters: []byte(`{"description":"d"}`), Rationale: "r"},
		"required parameter empty": {ActionType: "ticket.create",
			Targets:    []aggregate.TargetSpec{target("IT-OPS")},
			Parameters: []byte(`{"summary":""}`), Rationale: "r"},
		"parameters not an object": {ActionType: "ticket.create",
			Targets:    []aggregate.TargetSpec{target("IT-OPS")},
			Parameters: []byte(`["summary"]`), Rationale: "r"},
	}
	for name, req := range cases {
		if _, err := BuildRequestCommand(catalog, req, now); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}

	// The rejection message names the declared keys so a model caller can
	// self-correct in one round.
	_, err := BuildRequestCommand(catalog, ActionRequest{ActionType: "ticket.create",
		Targets:    []aggregate.TargetSpec{target("IT-OPS")},
		Parameters: []byte(`{"title":"t"}`), Rationale: "r"}, now)
	if err == nil || !strings.Contains(err.Error(), "summary") {
		t.Errorf("unknown-key error should name the declared inputs; got %v", err)
	}

	// Entity-typed inputs ride targets, not parameters: an action whose only
	// declared input is an entity accepts empty parameters, and an action with
	// optional string inputs accepts their absence.
	for _, ok := range []ActionRequest{
		{ActionType: "host.isolate", Targets: []aggregate.TargetSpec{target("WIN-A")}, Rationale: "r"},
		{ActionType: "ticket.close", Targets: []aggregate.TargetSpec{target("IT-1")}, Rationale: "r"}, // resolution is optional
		{ActionType: "ticket.create", Targets: []aggregate.TargetSpec{target("IT-OPS")},
			Parameters: []byte(`{"summary":"handoff"}`), Rationale: "r"},
	} {
		if _, err := BuildRequestCommand(catalog, ok, now); err != nil {
			t.Errorf("%s: unexpected rejection: %v", ok.ActionType, err)
		}
	}
}

// TestMaxTier: reversal tier parity (04 §7) — never lower than the original.
func TestMaxTier(t *testing.T) {
	if MaxTier(aggregate.TierT2, aggregate.TierT3) != aggregate.TierT3 {
		t.Error("T2 inverse of a T3 original must be T3")
	}
	if MaxTier(aggregate.TierT3, aggregate.TierT2) != aggregate.TierT3 {
		t.Error("T3 inverse of a T2 original stays T3")
	}
	if MaxTier(aggregate.TierT2, aggregate.TierT2) != aggregate.TierT2 {
		t.Error("equal tiers stay equal")
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
