package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/temporal"
)

// fakePipelineStarter records what the export endpoint asked to start.
type fakePipelineStarter struct {
	called bool
	in     temporal.ArchiveInvestigationInput
	wfID   string
}

func (f *fakePipelineStarter) StartPostConclusionPipeline(_ context.Context, in temporal.ArchiveInvestigationInput) (string, error) {
	f.called = true
	f.in = in
	if f.wfID == "" {
		f.wfID = "post-conclusion-" + in.GroupingID
	}
	return f.wfID, nil
}

func postExport(t *testing.T, b *Backend, token, id string) (*http.Response, ExportResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/investigations/"+id+"/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out ExportResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// concludeInvestigation drives an already-ACTIVE investigation to CONCLUDED,
// satisfying the conclude gate on the way (pin → verdict → conclude, 01).
func concludeInvestigation(t *testing.T, invID uuid.UUID) {
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
	if _, err := testHandler.Handle(context.Background(), env(), aggregate.ConcludeInvestigation{
		ReportRef: "report--1", Summary: "done",
	}); err != nil {
		t.Fatalf("conclude: %v", err)
	}
}

// TestExport_StartsPipelineWithPolicySideStores: a concluded investigation's
// export starts the pipeline, and IncludeSideStores comes from tenant POLICY
// (backend config), never the requester — the endpoint takes no such input.
func TestExport_StartsPipelineWithPolicySideStores(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	concludeInvestigation(t, invID)

	b := newTestBackend(t)
	b.cfg.TenantNamespace = uuid.NewString()
	b.cfg.ExportIncludeSideStores = false // compliance: redact Layer B
	fake := &fakePipelineStarter{}
	b.pipelineOverride = fake

	resp, out := postExport(t, b, mintToken(t, nil), invID.String())
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d; want 202", resp.StatusCode)
	}
	if !fake.called || out.WorkflowID == "" || out.Status != "STARTED" {
		t.Fatalf("pipeline not started cleanly: called=%v out=%+v", fake.called, out)
	}
	if fake.in.GroupingID != invID.String() || fake.in.TenantNamespace != b.cfg.TenantNamespace {
		t.Errorf("input = %+v; want grouping/namespace from the request+config", fake.in)
	}
	if fake.in.IncludeSideStores != false {
		t.Error("IncludeSideStores did not follow the tenant policy (false); requester must not override redaction")
	}
}

// TestExport_RejectsNonConcluded: an ACTIVE investigation cannot be exported.
func TestExport_RejectsNonConcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t) // ACTIVE

	b := newTestBackend(t)
	b.pipelineOverride = &fakePipelineStarter{}

	resp, _ := postExport(t, b, mintToken(t, nil), invID.String())
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d; want 409", resp.StatusCode)
	}
}

// TestExport_NoClient503: with no dispatch client (and no override) the endpoint
// reports the pipeline unavailable rather than pretending to start it.
func TestExport_NoClient503(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	concludeInvestigation(t, invID)

	b := newTestBackend(t) // no actionClient, no override
	resp, _ := postExport(t, b, mintToken(t, nil), invID.String())
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", resp.StatusCode)
	}
}

// TestExport_NotFound: exporting an unknown investigation is a 404.
func TestExport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	b.pipelineOverride = &fakePipelineStarter{}
	resp, _ := postExport(t, b, mintToken(t, nil), uuid.NewString())
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d; want 404", resp.StatusCode)
	}
}

// TestExportMarkdown_LiveProjection: GET /export.md renders at ANY lifecycle
// state (the live projection, binding §6 item 10) — unlike POST /export, which
// requires CONCLUDED. Frontmatter + sections speak engine vocabulary.
func TestExportMarkdown_LiveProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	env := func() aggregate.Envelope {
		return aggregate.Envelope{
			AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: "test-subject"}, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		}
	}
	// Pin + verdict, but do NOT conclude — mid-flight export is the point.
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

	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/investigations/"+invID.String()+"/export.md", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	body := make([]byte, 1<<20)
	n, _ := resp.Body.Read(body)
	md := string(body[:n])
	for _, want := range []string{
		"status: ACTIVE",
		"verdict: MALICIOUS",
		"## Pinned evidence",
		"load-bearing finding",
		"`observed-data--x`",
		"## Reasoning",
		"schema: reckon-export-md/1",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("export.md missing %q", want)
		}
	}
}
