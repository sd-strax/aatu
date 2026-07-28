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
	"github.com/sd-strax/reckon/module"
)

// draftInvestigation creates a fresh investigation (DRAFT) through the shared
// test handler and returns its id — the pre-activate state the lifecycle
// endpoint drives forward. activeInvestigation (actions_test.go) builds on it.
func draftInvestigation(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	env := newEnvelope(id, aggregate.Actor{PrincipalID: "test-subject"}, commandNow())
	if _, err := testHandler.Handle(context.Background(), env, aggregate.CreateInvestigation{Title: "INV"}); err != nil {
		t.Fatal(err)
	}
	return id
}

func postLifecycle(t *testing.T, b *Backend, token, id string, body LifecycleRequestBody) (*http.Response, LifecycleResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/investigations/"+id+"/lifecycle", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out LifecycleResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// TestLifecycle_ActivateDraft: a DRAFT investigation activates to ACTIVE.
func TestLifecycle_ActivateDraft(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := draftInvestigation(t)

	b := newTestBackend(t)
	resp, out := postLifecycle(t, b, mintToken(t, nil), invID.String(), LifecycleRequestBody{Transition: "activate"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if out.Status != aggregate.StatusActive || out.SequenceNo == 0 {
		t.Errorf("response = %+v; want ACTIVE with a sequence", out)
	}
}

// verdictFixture satisfies the conclude gate on an ACTIVE investigation:
// pin one evidence item, then record a verdict citing it (01 §Verdict).
func verdictFixture(t *testing.T, invID uuid.UUID) {
	t.Helper()
	env := func() aggregate.Envelope {
		return aggregate.Envelope{
			AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: "test-subject"}, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		}
	}
	if _, err := testHandler.Handle(context.Background(), env(), aggregate.RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: aggregate.InterpretationEvidencePin,
		InputRefs: []string{"observed-data--x"}, Rationale: "load-bearing finding",
	}); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := testHandler.Handle(context.Background(), env(), aggregate.RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: aggregate.InterpretationVerdict,
		Verdict:   &aggregate.VerdictNode{Disposition: aggregate.VerdictMalicious},
		InputRefs: []string{"observed-data--x"}, Rationale: "confirmed",
	}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
}

// TestLifecycle_ConcludeFiresExport: concluding an ACTIVE investigation returns
// 200 and, with auto-on-conclude enabled, fires the post-conclusion pipeline.
func TestLifecycle_ConcludeFiresExport(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	verdictFixture(t, invID)

	b := newTestBackend(t)
	b.cfg.TenantNamespace = uuid.NewString()
	b.cfg.ExportAutoOnConclude = true
	fake := &fakePipelineStarter{}
	b.pipelineOverride = fake

	resp, out := postLifecycle(t, b, mintToken(t, nil), invID.String(),
		LifecycleRequestBody{Transition: "conclude", ReportRef: "report--1", Summary: "done"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if out.Status != aggregate.StatusConcluded {
		t.Errorf("status = %q; want CONCLUDED", out.Status)
	}
	if !fake.called {
		t.Error("conclude did not fire the auto-export pipeline")
	}
	if fake.in.GroupingID != invID.String() {
		t.Errorf("export input grouping = %q; want %q", fake.in.GroupingID, invID)
	}
	if want := "post-conclusion-" + invID.String(); out.ExportWorkflowID != want {
		t.Errorf("export_workflow_id = %q; want %q (the started workflow must be correlatable)", out.ExportWorkflowID, want)
	}
}

// TestLifecycle_ConcludeNoAutoExport: with auto-on-conclude OFF, a conclude
// succeeds but does NOT start the pipeline (on-demand export only).
func TestLifecycle_ConcludeNoAutoExport(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	verdictFixture(t, invID)

	b := newTestBackend(t) // ExportAutoOnConclude defaults false
	fake := &fakePipelineStarter{}
	b.pipelineOverride = fake

	resp, _ := postLifecycle(t, b, mintToken(t, nil), invID.String(),
		LifecycleRequestBody{Transition: "conclude", ReportRef: "report--1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if fake.called {
		t.Error("auto-export fired despite ExportAutoOnConclude=false")
	}
}

// TestLifecycle_ConcludeRequiresReportRef: the one shape guard the endpoint owns
// — conclude without a report_ref is a 400 before the aggregate is touched.
func TestLifecycle_ConcludeRequiresReportRef(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)

	b := newTestBackend(t)
	resp, _ := postLifecycle(t, b, mintToken(t, nil), invID.String(),
		LifecycleRequestBody{Transition: "conclude"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

// TestLifecycle_IllegalTransitionRejected: a well-formed but illegal move
// (conclude from DRAFT) is the aggregate's to reject — surfaced as 422.
func TestLifecycle_IllegalTransitionRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := draftInvestigation(t) // DRAFT, not ACTIVE

	b := newTestBackend(t)
	resp, _ := postLifecycle(t, b, mintToken(t, nil), invID.String(),
		LifecycleRequestBody{Transition: "conclude", ReportRef: "report--1"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", resp.StatusCode)
	}
}

// TestLifecycle_AIDelegateBarredFromConclude: conclude is a human act — an
// AI-delegated token (delegate_kind set) is rejected by the aggregate allowlist,
// not merely by the endpoint, so the guard is a real second layer (04 §5.6). A
// permission denial surfaces as 403, matching the approval endpoints' mapping
// for the same AI-write-protection class.
func TestLifecycle_AIDelegateBarredFromConclude(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)

	b := newTestBackend(t)
	token := mintToken(t, map[string]any{"delegate_kind": "claude"})
	resp, _ := postLifecycle(t, b, token, invID.String(),
		LifecycleRequestBody{Transition: "conclude", ReportRef: "report--1"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403 (AI barred from conclude)", resp.StatusCode)
	}
}

// TestLifecycle_UnknownInvestigation: a transition addressed to an id with no
// event stream is a 404 — consistent with GET /investigations/{id} and
// POST .../export, not a 422.
func TestLifecycle_UnknownInvestigation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)

	b := newTestBackend(t)
	resp, _ := postLifecycle(t, b, mintToken(t, nil), uuid.NewString(),
		LifecycleRequestBody{Transition: "activate"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d; want 404", resp.StatusCode)
	}
}

// TestLifecycle_UnknownTransition: an unrecognized verb is a 400.
func TestLifecycle_UnknownTransition(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := draftInvestigation(t)

	b := newTestBackend(t)
	resp, _ := postLifecycle(t, b, mintToken(t, nil), invID.String(),
		LifecycleRequestBody{Transition: "teleport"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}
