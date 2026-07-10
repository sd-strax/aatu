package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
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
