package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/module"
)

// activeInvestigation drives a fresh investigation to ACTIVE through the shared
// test handler and returns its id, so an action can be requested against it.
func activeInvestigation(t *testing.T) uuid.UUID {
	t.Helper()
	id := draftInvestigation(t)
	env := newEnvelope(id, aggregate.Actor{PrincipalID: "test-subject"}, commandNow())
	if _, err := testHandler.Handle(context.Background(), env, aggregate.ActivateInvestigation{}); err != nil {
		t.Fatal(err)
	}
	return id
}

// actionBackend wires a backend with Gate 2 (the given policies) + the default
// action catalog. No Temporal client (auto-approve returns APPROVED, no wf id).
func actionBackend(t *testing.T, policies ...action.Policy) *Backend {
	t.Helper()
	b := newTestBackend(t)
	g, err := action.NewGate2(policies)
	if err != nil {
		t.Fatalf("NewGate2: %v", err)
	}
	b.cfg.Gate2 = g
	b.cfg.ActionCatalog = action.DefaultActionCatalog()
	return b
}

func postAction(t *testing.T, b *Backend, token string, body RequestActionBody) (*http.Response, RequestActionResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/actions", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out RequestActionResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// TestRequestAction_AutoApprove: a matching AUTO_APPROVE policy (signed off by a
// human) auto-approves; the x-action lands APPROVED, attributed to that human.
func TestRequestAction_AutoApprove(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)

	b := actionBackend(t, action.Policy{
		ID: "policy/auto-isolate/1.0.0", ActionMatch: []string{"host.isolate"},
		Effect: action.EffectAutoApprove, Predicate: "true", SignedOffBy: []string{"secops-lead"},
	})

	resp, out := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want 201", resp.StatusCode)
	}
	if out.Mode != action.ModeAutoPolicy || out.Status != "APPROVED" {
		t.Errorf("mode=%q status=%q; want AUTO_POLICY/APPROVED", out.Mode, out.Status)
	}

	// The projection reflects APPROVED, attributed to the policy's human.
	ac, err := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(out.ActionID))
	if err != nil {
		t.Fatalf("LoadActionCurrent: %v", err)
	}
	if ac.Status != aggregate.ActionStatusApproved || ac.PrimaryApprover != "secops-lead" {
		t.Errorf("projected status=%q approver=%q; want APPROVED / secops-lead", ac.Status, ac.PrimaryApprover)
	}
}

// TestRequestAction_ManualFallThrough: with no matching policy the action is
// created REQUESTED and left for manual approval.
func TestRequestAction_ManualFallThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t) // baseline only

	_, out := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	if out.Status != "PENDING_MANUAL" || out.Mode != action.ModeManual {
		t.Errorf("status=%q mode=%q; want PENDING_MANUAL/MANUAL", out.Status, out.Mode)
	}
	ac, _ := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(out.ActionID))
	if ac.Status != aggregate.ActionStatusRequested {
		t.Errorf("projected status = %q; want REQUESTED", ac.Status)
	}
}

// succeededAction drives an x-action through request → approve → dispatch →
// result SUCCEEDED on the given investigation, returning its id.
func succeededAction(t *testing.T, invID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	actionID := uuid.New()
	env := func(kind string) aggregate.Envelope {
		return aggregate.Envelope{
			AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: "test-subject", Kind: kind}, OccurredAt: time.Now().UTC(),
		}
	}
	mustDo := func(e aggregate.Envelope, cmd aggregate.Command) {
		t.Helper()
		if _, err := testHandler.Handle(ctx, e, cmd); err != nil {
			t.Fatalf("%s: %v", cmd.Kind(), err)
		}
	}
	mustDo(env(""), aggregate.RequestAction{
		ActionID: actionID, ActionType: "host.isolate", Tier: aggregate.TierT2,
		Targets:   []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		ExpiresAt: time.Now().Add(time.Hour), Rationale: "contain",
	})
	mustDo(env(""), aggregate.ApproveAction{
		ActionID: actionID,
		Authorization: aggregate.Authorization{
			Mode: aggregate.AuthModeManual, Stage: aggregate.AuthStageSolo,
			PrimaryApproverRef: "test-subject", PrimaryApprovedAt: time.Now(),
		},
	})
	mustDo(env(aggregate.ActorSystem), aggregate.DispatchAction{ActionID: actionID, Adapter: "fx", AdapterRequestID: "wf"})
	mustDo(env(aggregate.ActorSystem), aggregate.ResultAction{ActionID: actionID, FinalOutcome: "SUCCEEDED", Attempts: 1})
	return actionID
}

// TestRerequestAction: re-requesting an EXPIRED action creates a NEW action
// with the original's frozen fields, retry_of lineage, and a fresh clock — the
// analyst's re-affirmation, not a bypass of expiry. A live action can't be
// re-requested.
func TestRerequestAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t) // baseline only — lands PENDING_MANUAL

	// Request an action, then expire it (SYSTEM-emitted, as the timer would).
	_, orig := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--9", ResolvedIdentifier: "WIN-9"}},
		EvidenceRefs:     []string{"observed-data--od9"},
		Rationale:        "original containment rationale",
		InvestigationRef: invID.String(),
	})
	origID := uuid.MustParse(orig.ActionID)

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	rerequest := func(id, rationale string) (*http.Response, RequestActionResponse) {
		raw, _ := json.Marshal(RerequestBody{Rationale: rationale})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/actions/"+id+"/rerequest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out RequestActionResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		return resp, out
	}

	// A live (PENDING_MANUAL) action is not re-requestable.
	if resp, _ := rerequest(orig.ActionID, "too soon"); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("re-request of a live action = %d; want 422", resp.StatusCode)
	}

	// Expire it (SYSTEM actor, as the Temporal timer does).
	expEnv := aggregate.Envelope{
		AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
		Actor: aggregate.Actor{PrincipalID: "system", Kind: aggregate.ActorSystem}, OccurredAt: time.Now().UTC(),
	}
	if _, err := testHandler.Handle(context.Background(), expEnv, aggregate.ExpireAction{ActionID: origID}); err != nil {
		t.Fatalf("expire: %v", err)
	}

	// Now re-request: a NEW action, PENDING_MANUAL, with retry_of lineage and
	// the frozen fields carried faithfully.
	resp, out := rerequest(orig.ActionID, "still warranted — host still shows the beacon")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("re-request = %d; want 201", resp.StatusCode)
	}
	if out.ActionID == orig.ActionID {
		t.Fatal("re-request reused the original id; a retry must be a NEW action")
	}
	newID := uuid.MustParse(out.ActionID)
	nc, err := aggregate.LoadActionCurrent(context.Background(), testDB, newID)
	if err != nil {
		t.Fatalf("load new action: %v", err)
	}
	if nc.Status != aggregate.ActionStatusRequested {
		t.Errorf("new action status = %q; want REQUESTED (fresh, awaiting approval)", nc.Status)
	}
	if nc.RetryOf != origID {
		t.Errorf("retry_of = %s; want the original %s", nc.RetryOf, origID)
	}
	if nc.ActionType != "host.isolate" || len(nc.Targets) != 1 || nc.Targets[0].ResolvedIdentifier != "WIN-9" {
		t.Errorf("frozen fields not carried: %+v", nc)
	}
	if len(nc.EvidenceRefs) != 1 || nc.EvidenceRefs[0] != "observed-data--od9" {
		t.Errorf("evidence not carried: %v", nc.EvidenceRefs)
	}
	// Fresh clock: the new window is in the future.
	if !nc.ExpiresAt.After(time.Now()) {
		t.Errorf("new expires_at = %v; want a fresh future window", nc.ExpiresAt)
	}
}

// TestRequestAction_ReversalValidation: a reversal request must name a real,
// SUCCEEDED original whose descriptor's reversible_by matches the requested
// action_type (04 §7) — otherwise the eventual action.reversed would lie.
func TestRequestAction_ReversalValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	origID := succeededAction(t, invID)
	b := actionBackend(t) // baseline only — reversal lands PENDING_MANUAL

	post := func(body RequestActionBody) (*http.Response, RequestActionResponse) {
		return postAction(t, b, mintToken(t, nil), body)
	}
	revTarget := []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}}

	// Nonexistent original → 422.
	resp, _ := post(RequestActionBody{
		ActionType: "host.unisolate", Targets: revTarget, Rationale: "undo",
		InvestigationRef: invID.String(), ReversalOfRef: uuid.NewString(),
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("nonexistent original: status %d; want 422", resp.StatusCode)
	}

	// Wrong inverse type (email.release does not reverse host.isolate) → 422.
	resp, _ = post(RequestActionBody{
		ActionType: "email.release", Targets: revTarget, Rationale: "undo",
		InvestigationRef: invID.String(), ReversalOfRef: origID.String(),
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("wrong inverse type: status %d; want 422", resp.StatusCode)
	}

	// Correct inverse → 201, REQUESTED, tier parity held (both T2 here).
	resp, out := post(RequestActionBody{
		ActionType: "host.unisolate", Targets: revTarget, Rationale: "undo",
		InvestigationRef: invID.String(), ReversalOfRef: origID.String(),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("valid reversal: status %d; want 201", resp.StatusCode)
	}
	if out.Tier != aggregate.TierT2 || out.Status != "PENDING_MANUAL" {
		t.Errorf("valid reversal: tier=%q status=%q; want T2/PENDING_MANUAL", out.Tier, out.Status)
	}
}

// TestListActionTypes: GET /api/action-types surfaces the frozen write catalog
// with per-type dispatchability, so the agent requests real action types instead
// of guessing. With no bindings every type reports unavailable — the honest view.
func TestListActionTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.ActionCatalog = action.DefaultActionCatalog()
	b.cfg.ActionResolver = action.NewActionResolver(nil, nil) // no bindings → all unavailable

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/action-types", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	var out struct {
		ActionTypes []action.ActionSummary `json:"action_types"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	byType := map[string]action.ActionSummary{}
	for _, a := range out.ActionTypes {
		byType[a.Descriptor.ActionType] = a
	}
	// The frozen block action is present, correctly named and annotated — the
	// exact type the agent guessed wrong in the road test.
	ioc, ok := byType["ioc.block"]
	if !ok {
		t.Fatalf("ioc.block missing from catalog; got %v", byType)
	}
	if ioc.Descriptor.D3FEND != "D3-NTF" || ioc.Descriptor.DefaultTier != "T2" {
		t.Errorf("ioc.block descriptor wrong: %+v", ioc.Descriptor)
	}
	if ioc.Status != action.ActionUnavailable {
		t.Errorf("ioc.block status = %q; want unavailable (no binding)", ioc.Status)
	}
	if _, ok := byType["host.isolate"]; !ok {
		t.Error("host.isolate missing from catalog")
	}
}

// TestListActionTypes_ServiceUnavailable: with no action layer configured the
// route is a clean 503, not a panic.
func TestListActionTypes_ServiceUnavailable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t) // no ActionCatalog / ActionResolver
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/action-types", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", resp.StatusCode)
	}
}

// TestListInvestigationActions: GET /api/investigations/{id}/actions returns
// the durable action queue — every x-action with its raw status, required mode,
// and targets — so a surface can recover pending approvals after the turn that
// proposed them is gone.
func TestListInvestigationActions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t) // baseline only — requests land REQUESTED/MANUAL

	_, first := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-FILE01"}},
		EvidenceRefs:     []string{"observed-data--od1"},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	_, second := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "account.disable",
		Targets:          []aggregate.TargetSpec{{EntityRef: "user-account--1", ResolvedIdentifier: "svc_backup"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/investigations/"+invID.String()+"/actions", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	var out struct {
		Actions []ActionView `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Actions) != 2 {
		t.Fatalf("actions = %d; want 2", len(out.Actions))
	}
	byID := map[string]ActionView{}
	for _, a := range out.Actions {
		byID[a.ActionID] = a
	}
	iso, ok := byID[first.ActionID]
	if !ok {
		t.Fatalf("host.isolate %s missing from list %+v", first.ActionID, out.Actions)
	}
	if iso.ActionType != "host.isolate" || iso.Status != aggregate.ActionStatusRequested ||
		iso.RequiredMode != aggregate.AuthModeManual ||
		len(iso.Targets) != 1 || iso.Targets[0].ResolvedIdentifier != "WIN-FILE01" {
		t.Errorf("host.isolate row mangled: %+v", iso)
	}
	// The grounding surfaces on the durable view (10 §3 G1 reads it here).
	if len(iso.EvidenceRefs) != 1 || iso.EvidenceRefs[0] != "observed-data--od1" {
		t.Errorf("evidence_refs not served: %+v", iso.EvidenceRefs)
	}
	if dis := byID[second.ActionID]; dis.ActionType != "account.disable" {
		t.Errorf("account.disable row mangled: %+v", dis)
	}
}

// TestRequestAction_AIDelegatedT3BaselineDeny: an AI-delegated request that
// escalates to T3 can never auto-approve — the baseline DENY forces manual,
// even with a matching AUTO_APPROVE policy. Actor.Kind comes from the JWT
// delegate_kind claim, not the body.
func TestRequestAction_AIDelegatedT3BaselineDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)

	b := actionBackend(t, action.Policy{
		ID: "policy/auto-purge/1.0.0", ActionMatch: []string{"email.purge"},
		Effect: action.EffectAutoApprove, Predicate: "true", SignedOffBy: []string{"lead"},
	})

	// email.purge is T3 (irreversible). AI-delegated token → baseline DENY.
	token := mintToken(t, map[string]any{"delegate_kind": "claude"})
	_, out := postAction(t, b, token, RequestActionBody{
		ActionType:       "email.purge",
		Targets:          []aggregate.TargetSpec{{EntityRef: "email-message--1", ResolvedIdentifier: "<msg@x>"}},
		Rationale:        "phish",
		InvestigationRef: invID.String(),
	})
	if out.Tier != aggregate.TierT3 {
		t.Errorf("tier = %q; want T3", out.Tier)
	}
	if out.Status == "APPROVED" {
		t.Errorf("AI-delegated T3 was auto-approved (%q); the baseline DENY must force manual", out.Status)
	}
}
