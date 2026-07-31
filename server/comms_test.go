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

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/comms"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/temporal"
)

// TestComms_NotifyResultOpensThread: the Phase F seam end to end at the
// engine level — a notify.slack action that reaches SUCCEEDED opens a comms
// thread (via the result activity's hook), a follow-up notify carrying
// thread_ref extends it, and an inbound reply + ack + done walk the thread's
// state machine through the HTTP surface.
func TestComms_NotifyResultOpensThread(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	if _, err := testDB.Exec(`TRUNCATE comms_threads`); err != nil {
		t.Fatalf("truncate comms_threads: %v", err)
	}
	invID := activeInvestigation(t)
	store := comms.NewStore(testDB)
	acts := temporal.NewActivities(testHandler, nil).WithComms(store)

	env := func() aggregate.Envelope {
		return newEnvelope(invID, aggregate.Actor{PrincipalID: "test-subject"}, commandNow())
	}
	runToSuccess := func(t *testing.T, actionID uuid.UUID, params string) {
		t.Helper()
		if _, err := testHandler.Handle(context.Background(), env(), aggregate.RequestAction{
			ActionID: actionID, ActionType: "notify.slack", Tier: aggregate.TierT2,
			Targets:    []aggregate.TargetSpec{{ResolvedIdentifier: "#it-operations"}},
			Parameters: json.RawMessage(params),
			ExpiresAt:  time.Now().Add(time.Hour), Rationale: "coordinate reimage",
		}); err != nil {
			t.Fatalf("request: %v", err)
		}
		if _, err := testHandler.Handle(context.Background(), env(), aggregate.ApproveAction{
			ActionID: actionID,
			Authorization: aggregate.Authorization{
				Mode: aggregate.AuthModeManual, Stage: aggregate.AuthStageSolo,
				PrimaryApproverRef: "test-subject", PrimaryApprovedAt: time.Now(),
			},
		}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if err := acts.EmitDispatched(context.Background(), temporal.EmitDispatchedInput{
			ActionID: actionID.String(), AggregateID: invID.String(),
			TenantID: module.SingleTenantUUID.String(), ApproverID: "test-subject",
			Adapter: "fixture_write", AdapterRequestID: "wf-" + actionID.String(),
		}); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if err := acts.EmitResulted(context.Background(), temporal.EmitResultedInput{
			ActionID: actionID.String(), AggregateID: invID.String(),
			TenantID: module.SingleTenantUUID.String(), ApproverID: "test-subject",
			FinalOutcome: "SUCCEEDED", PerTargetResults: map[string]string{"0": "OK"}, Attempts: 1,
		}); err != nil {
			t.Fatalf("result: %v", err)
		}
	}

	// 1. The first send opens the thread.
	runToSuccess(t, uuid.New(), `{"message":"WIN-FILE01 is isolated and ready for reimage","follow_up_hours":48}`)
	threads, err := store.List(context.Background(), invID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 {
		t.Fatalf("threads = %d; want 1", len(threads))
	}
	th := threads[0]
	if th.Target != "#it-operations" || th.Status != comms.StatusAwaitingReply ||
		th.FollowUpHours != 48 || len(th.Trail) != 1 || th.Trail[0].Direction != comms.DirOutbound {
		t.Fatalf("thread = %+v; want awaiting_reply on #it-operations with one outbound entry", th)
	}
	if !th.NextFollowUpAt.Valid {
		t.Error("follow-up clock not set")
	}

	// 2. A follow-up (thread_ref) extends the SAME thread.
	runToSuccess(t, uuid.New(), `{"message":"Any update on the reimage?","thread_ref":"`+th.ThreadID.String()+`"}`)
	threads, _ = store.List(context.Background(), invID, time.Now())
	if len(threads) != 1 || threads[0].FollowUps != 1 || len(threads[0].Trail) != 2 {
		t.Fatalf("after follow-up: threads=%d followups=%d trail=%d; want 1/1/2",
			len(threads), threads[0].FollowUps, len(threads[0].Trail))
	}

	// 3. The HTTP surface: inbound reply → replied+unacked; ack; done.
	b := newTestBackend(t)
	b.cfg.Comms = store
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	token := mintToken(t, nil)
	post := func(path string, body any) int {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("/api/comms/inbound", CommsInboundBody{
		ThreadID: th.ThreadID.String(), Author: "Mike Torres", Body: "Reimage scheduled for tomorrow.",
	}); code != http.StatusOK {
		t.Fatalf("inbound = %d", code)
	}
	threads, _ = store.List(context.Background(), invID, time.Now())
	if threads[0].Status != comms.StatusReplied || !threads[0].UnackedReply {
		t.Fatalf("after inbound: %+v; want replied+unacked", threads[0])
	}
	if code := post("/api/comms/"+th.ThreadID.String()+"/ack", map[string]any{}); code != http.StatusOK {
		t.Fatalf("ack = %d", code)
	}
	if code := post("/api/comms/"+th.ThreadID.String()+"/done", map[string]any{}); code != http.StatusOK {
		t.Fatalf("done = %d", code)
	}
	threads, _ = store.List(context.Background(), invID, time.Now())
	if threads[0].Status != comms.StatusClosed || threads[0].UnackedReply {
		t.Fatalf("after done: %+v; want closed", threads[0])
	}

	// 4. GET serves the thread with its trail.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/investigations/"+invID.String()+"/comms", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Threads []CommsThreadView `json:"threads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Threads) != 1 || len(out.Threads[0].Trail) < 4 {
		t.Fatalf("served threads=%d trail=%d; want the full trail (send, follow-up, reply, notes)",
			len(out.Threads), len(out.Threads[0].Trail))
	}
}

// TestComms_EscalationDerivedNotFired: the stale policy computes as a PROMPT
// on read (2+ follow-ups, >72h, still awaiting) — no state is changed and
// nothing fires; v0 policies surface prompts only.
func TestComms_EscalationDerivedNotFired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	if _, err := testDB.Exec(`TRUNCATE comms_threads`); err != nil {
		t.Fatal(err)
	}
	invID := activeInvestigation(t)
	store := comms.NewStore(testDB)
	old := time.Now().Add(-80 * time.Hour)
	if err := store.Outbound(context.Background(), comms.OutboundMessage{
		AggregateID: invID, TenantID: module.SingleTenantUUID, ActionID: uuid.New(),
		ActionType: "notify.slack", Target: "#x", Subject: "stale item",
		Body: "please handle", Author: "a", FollowUpHours: 24, At: old,
	}); err != nil {
		t.Fatal(err)
	}
	threads, _ := store.List(context.Background(), invID, time.Now())
	id := threads[0].ThreadID
	for i := 0; i < 2; i++ {
		if err := store.Outbound(context.Background(), comms.OutboundMessage{
			AggregateID: invID, TenantID: module.SingleTenantUUID, ActionID: uuid.New(),
			ActionType: "notify.slack", Target: "#x", Body: "ping", Author: "a",
			At: old.Add(time.Duration(i+1) * 24 * time.Hour), ThreadRef: id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	threads, _ = store.List(context.Background(), invID, time.Now())
	th := threads[0]
	if !th.EscalationTriggered || th.EscalationPolicy != comms.StalePolicyID {
		t.Errorf("escalation not derived: %+v", th)
	}
	if th.Status == comms.StatusClosed {
		t.Error("a derived policy must never change thread state")
	}
	if !th.FollowUpDue {
		t.Error("follow-up dueness not derived for an elapsed clock")
	}
}
