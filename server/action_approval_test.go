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

// postActionDecision POSTs to /api/actions/{id}/{verb} and returns the response.
func postActionDecision(t *testing.T, b *Backend, token, id, verb string, body any) (*http.Response, ActionDecisionResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/actions/"+id+"/"+verb, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out ActionDecisionResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// requestManualAction posts a request_action with no matching policy → the
// action lands PENDING_MANUAL. Returns its id.
func requestManualAction(t *testing.T, b *Backend, invID uuid.UUID) string {
	t.Helper()
	_, out := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	if out.Status != "PENDING_MANUAL" {
		t.Fatalf("setup: status = %q; want PENDING_MANUAL", out.Status)
	}
	return out.ActionID
}

// TestApproveAction_ManualSolo: a manual action is approved by a single analyst
// (SOLO) and lands APPROVED.
func TestApproveAction_ManualSolo(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t) // baseline only → manual

	actionID := requestManualAction(t, b, invID)
	resp, out := postActionDecision(t, b, mintToken(t, nil), actionID, "approve", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if out.Status != aggregate.ActionStatusApproved || out.Stage != aggregate.AuthStageSolo {
		t.Errorf("out = %+v; want APPROVED/SOLO", out)
	}

	ac, _ := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(actionID))
	if ac.Status != aggregate.ActionStatusApproved || ac.PrimaryApprover != "test-subject" {
		t.Errorf("projected %s/%s; want APPROVED/test-subject", ac.Status, ac.PrimaryApprover)
	}
}

// TestRejectAction: a manual action is rejected and lands REJECTED.
func TestRejectAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t)

	actionID := requestManualAction(t, b, invID)
	resp, out := postActionDecision(t, b, mintToken(t, nil), actionID, "reject", RejectActionBody{Reason: "not warranted"})
	if resp.StatusCode != http.StatusOK || out.Status != aggregate.ActionStatusRejected {
		t.Fatalf("resp %d out %+v; want 200/REJECTED", resp.StatusCode, out)
	}
	ac, _ := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(actionID))
	if ac.Status != aggregate.ActionStatusRejected {
		t.Errorf("projected %s; want REJECTED", ac.Status)
	}
}

// TestApproveAction_TwoPartyFlow: a REQUIRE_TWO_PARTY action needs two distinct
// approvers. The first approval → PENDING_SECONDARY (no dispatch); the same
// approver again → rejected; a second, in-pool approver → APPROVED.
func TestApproveAction_TwoPartyFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t, action.Policy{
		ID: "policy/two-party-isolate/1.0.0", ActionMatch: []string{"host.isolate"},
		Effect: action.EffectRequireTwoParty, Predicate: "true", SecondaryApproverPool: []string{"bob"},
	})

	// Request → PENDING_TWO_PARTY.
	_, req := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	if req.Status != "PENDING_TWO_PARTY" {
		t.Fatalf("request status = %q; want PENDING_TWO_PARTY", req.Status)
	}
	actionID := req.ActionID

	// Primary approval (test-subject) → PENDING_SECONDARY, no workflow.
	_, out := postActionDecision(t, b, mintToken(t, nil), actionID, "approve", nil)
	if out.Status != aggregate.ActionStatusPendingSecondary || out.Stage != aggregate.AuthStagePrimary {
		t.Fatalf("primary approval out = %+v; want PENDING_SECONDARY/PRIMARY", out)
	}

	// The same principal cannot complete the second stage — two humans required.
	resp, _ := postActionDecision(t, b, mintToken(t, nil), actionID, "approve", nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("same-approver secondary: status %d; want 422", resp.StatusCode)
	}

	// A distinct, in-pool approver (bob) completes it → APPROVED.
	bob := mintToken(t, map[string]any{"sub": "bob"})
	resp, out = postActionDecision(t, b, bob, actionID, "approve", nil)
	if resp.StatusCode != http.StatusOK || out.Status != aggregate.ActionStatusApproved || out.Stage != aggregate.AuthStageSecondary {
		t.Fatalf("secondary approval resp %d out %+v; want 200 APPROVED/SECONDARY", resp.StatusCode, out)
	}
	ac, _ := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(actionID))
	if ac.Status != aggregate.ActionStatusApproved {
		t.Errorf("projected %s; want APPROVED", ac.Status)
	}
}

// TestApproveAction_SecondaryCarriesPrimaryTime: the final (secondary-stage)
// authorization record must cite the PRIMARY approval's true timestamp — never
// the secondary's clock. This is the citable record for a two-party action; a
// fabricated primary time is an audit lie.
func TestApproveAction_SecondaryCarriesPrimaryTime(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t, action.Policy{
		ID: "policy/two-party-isolate/1.0.0", ActionMatch: []string{"host.isolate"},
		Effect: action.EffectRequireTwoParty, Predicate: "true",
	})

	_, req := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "host.isolate",
		Targets:          []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		Rationale:        "contain",
		InvestigationRef: invID.String(),
	})
	actionID := req.ActionID

	// Primary approval; capture its recorded time from the projection.
	if _, out := postActionDecision(t, b, mintToken(t, nil), actionID, "approve", nil); out.Status != aggregate.ActionStatusPendingSecondary {
		t.Fatalf("primary: %+v", out)
	}
	acAfterPrimary, err := aggregate.LoadActionCurrent(context.Background(), testDB, uuid.MustParse(actionID))
	if err != nil || acAfterPrimary.PrimaryApprovedAt.IsZero() {
		t.Fatalf("projection primary_approved_at missing: %+v err=%v", acAfterPrimary, err)
	}
	primaryTime := acAfterPrimary.PrimaryApprovedAt

	// Secondary approval by a distinct approver, strictly later.
	time.Sleep(5 * time.Millisecond)
	bob := mintToken(t, map[string]any{"sub": "bob"})
	if resp, out := postActionDecision(t, b, bob, actionID, "approve", nil); resp.StatusCode != http.StatusOK || out.Status != aggregate.ActionStatusApproved {
		t.Fatalf("secondary: %d %+v", resp.StatusCode, out)
	}

	// The FINAL approval event's authorization cites the true primary time.
	var payload []byte
	if err := testDB.QueryRow(`
		SELECT payload FROM events
		WHERE aggregate_id = $1 AND event_type = 'action.approved'
		ORDER BY sequence_no DESC LIMIT 1
	`, invID).Scan(&payload); err != nil {
		t.Fatalf("final approval event: %v", err)
	}
	var evt struct {
		Authorization aggregate.Authorization `json:"authorization"`
	}
	if err := json.Unmarshal(payload, &evt); err != nil {
		t.Fatal(err)
	}
	if !evt.Authorization.PrimaryApprovedAt.Equal(primaryTime) {
		t.Errorf("final record primary_approved_at = %v; want the primary's true time %v",
			evt.Authorization.PrimaryApprovedAt, primaryTime)
	}
	if evt.Authorization.SecondaryApprovedAt == nil || !evt.Authorization.SecondaryApprovedAt.After(primaryTime) {
		t.Errorf("secondary_approved_at = %v; want strictly after the primary's %v",
			evt.Authorization.SecondaryApprovedAt, primaryTime)
	}
}

// TestApproveAction_ExpiredRejected: no expiry timer runs in v0, so the
// endpoint is the enforcement point — a lapsed request cannot be approved as if
// its TTL meant nothing.
func TestApproveAction_ExpiredRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t)

	// Drive a request with an already-past expiry directly through the handler.
	actionID := uuid.New()
	env := aggregate.Envelope{
		AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
		Actor: aggregate.Actor{PrincipalID: "test-subject"}, OccurredAt: time.Now().UTC(),
	}
	if _, err := testHandler.Handle(context.Background(), env, aggregate.RequestAction{
		ActionID: actionID, ActionType: "host.isolate", Tier: aggregate.TierT2,
		Targets:   []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		ExpiresAt: time.Now().Add(-time.Hour), Rationale: "stale",
	}); err != nil {
		t.Fatal(err)
	}

	resp, _ := postActionDecision(t, b, mintToken(t, nil), actionID.String(), "approve", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expired approve: status %d; want 409", resp.StatusCode)
	}
}

// TestApproveAction_T3RequiresChallenge: a T3 approval without the typed
// challenge is refused — the intent-proving field can never be silently absent
// from a T3 authorization record (04 §5.5).
func TestApproveAction_T3RequiresChallenge(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t)

	// email.purge is T3; no policy → PENDING_MANUAL.
	_, req := postAction(t, b, mintToken(t, nil), RequestActionBody{
		ActionType:       "email.purge",
		Targets:          []aggregate.TargetSpec{{EntityRef: "email-message--1", ResolvedIdentifier: "<msg@x>"}},
		Rationale:        "phish",
		InvestigationRef: invID.String(),
	})
	if req.Tier != aggregate.TierT3 {
		t.Fatalf("setup: tier %q; want T3", req.Tier)
	}

	resp, _ := postActionDecision(t, b, mintToken(t, nil), req.ActionID, "approve", nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("T3 approve without challenge: status %d; want 422", resp.StatusCode)
	}
	resp, out := postActionDecision(t, b, mintToken(t, nil), req.ActionID, "approve",
		ApproveActionBody{ChallengeResponse: "purge <msg@x>"})
	if resp.StatusCode != http.StatusOK || out.Status != aggregate.ActionStatusApproved {
		t.Errorf("T3 approve with challenge: %d %+v; want 200 APPROVED", resp.StatusCode, out)
	}
}

// TestApproveAction_UnfrozenTwoPartySecondary: an action already sitting in
// PENDING_SECONDARY completes as two-party even when no requirement was frozen
// at request time — it must never fall through to a solo path or get stuck.
func TestApproveAction_UnfrozenTwoPartySecondary(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t)

	// Request + two-party PRIMARY recorded via direct commands (no frozen
	// required_mode on the request).
	actionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	env := func(principal string) aggregate.Envelope {
		return aggregate.Envelope{
			AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: principal}, OccurredAt: now,
		}
	}
	if _, err := testHandler.Handle(context.Background(), env("alice"), aggregate.RequestAction{
		ActionID: actionID, ActionType: "host.isolate", Tier: aggregate.TierT2,
		Targets:   []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		ExpiresAt: time.Now().Add(time.Hour), Rationale: "contain",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := testHandler.Handle(context.Background(), env("alice"), aggregate.ApproveAction{
		ActionID: actionID,
		Authorization: aggregate.Authorization{
			Mode: aggregate.AuthModeTwoParty, Stage: aggregate.AuthStagePrimary,
			PrimaryApproverRef: "alice", PrimaryApprovedAt: now,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// A distinct approver completes it via the endpoint.
	bob := mintToken(t, map[string]any{"sub": "bob"})
	resp, out := postActionDecision(t, b, bob, actionID.String(), "approve", nil)
	if resp.StatusCode != http.StatusOK || out.Status != aggregate.ActionStatusApproved || out.Stage != aggregate.AuthStageSecondary {
		t.Errorf("unfrozen two-party secondary: %d %+v; want 200 APPROVED/SECONDARY", resp.StatusCode, out)
	}
}

// TestApproveAction_AIDelegatedForbidden: an AI delegate cannot approve — the
// endpoint refuses it (403) before the aggregate ever sees it.
func TestApproveAction_AIDelegatedForbidden(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := actionBackend(t)

	actionID := requestManualAction(t, b, invID)
	token := mintToken(t, map[string]any{"delegate_kind": "claude"})
	resp, _ := postActionDecision(t, b, token, actionID, "approve", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AI-delegated approve: status %d; want 403", resp.StatusCode)
	}
}

// TestApproveAction_NotFound: approving an unknown action id is a 404.
func TestApproveAction_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := actionBackend(t)
	resp, _ := postActionDecision(t, b, mintToken(t, nil), uuid.NewString(), "approve", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown action approve: status %d; want 404", resp.StatusCode)
	}
}
