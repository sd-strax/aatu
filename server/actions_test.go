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
	id := uuid.New()
	env := func() aggregate.Envelope {
		return aggregate.Envelope{
			AggregateID: id, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: "test-subject"}, OccurredAt: time.Now().UTC(),
		}
	}
	if _, err := testHandler.Handle(context.Background(), env(), aggregate.CreateInvestigation{Title: "INV"}); err != nil {
		t.Fatal(err)
	}
	if _, err := testHandler.Handle(context.Background(), env(), aggregate.ActivateInvestigation{}); err != nil {
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
