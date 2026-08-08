package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// snowMock is a stateful ServiceNow Table API double: it stores incidents by
// sys_id, indexes correlation_id and number for the two query paths the adapter
// uses, and counts POSTs so a test can prove idempotent-create dedup.
type snowMock struct {
	mu        sync.Mutex
	byCorr    map[string]*mockRec
	byNumber  map[string]*mockRec
	bySysID   map[string]*mockRec
	seq        int
	postCount  int
	createBody map[string]any // last POST body, for assertion
	patchBody  map[string]any // last PATCH body, for assertion
}

type mockRec struct {
	SysID string
	Num   string
	State string
}

func newSNowMock() *snowMock {
	return &snowMock{
		byCorr: map[string]*mockRec{}, byNumber: map[string]*mockRec{}, bySysID: map[string]*mockRec{},
	}
}

// server wires the mock onto an httptest server. Basic auth is enforced
// (admin:secret) so the auth header is exercised.
func (m *snowMock) server(t *testing.T) *httptest.Server {
	t.Helper()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"User Not Authenticated"},"status":"failure"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			m.handleQuery(w, r)
		case http.MethodPost:
			m.handleCreate(w, r)
		case http.MethodPatch:
			m.handlePatch(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(h))
	t.Cleanup(srv.Close)
	return srv
}

func (m *snowMock) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("sysparm_query")
	m.mu.Lock()
	defer m.mu.Unlock()
	var rec *mockRec
	if v, ok := strings.CutPrefix(q, "correlation_id="); ok {
		rec = m.byCorr[v]
	} else if v, ok := strings.CutPrefix(q, "number="); ok {
		rec = m.byNumber[v]
	}
	if rec == nil {
		_, _ = w.Write([]byte(`{"result":[]}`))
		return
	}
	_, _ = fmt.Fprintf(w, `{"result":[{"sys_id":%q,"number":%q,"state":%q}]}`, rec.SysID, rec.Num, rec.State)
}

func (m *snowMock) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.postCount++
	m.createBody = body
	m.seq++
	rec := &mockRec{
		SysID: fmt.Sprintf("%032x", m.seq),
		Num:   fmt.Sprintf("INC%07d", m.seq),
		State: "1",
	}
	m.bySysID[rec.SysID] = rec
	m.byNumber[rec.Num] = rec
	if corr, ok := body["correlation_id"].(string); ok && corr != "" {
		m.byCorr[corr] = rec
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, `{"result":{"sys_id":%q,"number":%q,"state":%q}}`, rec.SysID, rec.Num, rec.State)
}

func (m *snowMock) handlePatch(w http.ResponseWriter, r *http.Request) {
	sysID := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patchBody = body
	rec := m.bySysID[sysID]
	if rec == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"Record not found"},"status":"failure"}`))
		return
	}
	if s, ok := body["state"].(string); ok {
		rec.State = s
	}
	_, _ = fmt.Fprintf(w, `{"result":{"sys_id":%q,"number":%q,"state":%q}}`, rec.SysID, rec.Num, rec.State)
}

// configuredBridge builds a bridge pointing at baseURL with the mock's creds.
func configuredBridge(t *testing.T, baseURL string) *bridge {
	t.Helper()
	b := newBridge()
	cfg, _ := json.Marshal(adapterplugin.ConfigureParams{Config: map[string]any{
		"instance_url": baseURL, "username": "admin", "password": "secret",
	}})
	if _, werr := b.configure(cfg); werr != nil {
		t.Fatalf("configure: %v", werr)
	}
	return b
}

func dispatch(t *testing.T, b *bridge, op string, params map[string]any, idem string) action.WriteResult {
	t.Helper()
	raw, _ := json.Marshal(adapterplugin.DispatchParams{Operation: op, Params: params, IdempotencyKey: idem})
	res, werr := b.dispatch(context.Background(), raw)
	if werr != nil {
		t.Fatalf("dispatch %s wire error: %v", op, werr)
	}
	wr, ok := res.(action.WriteResult)
	if !ok {
		t.Fatalf("dispatch result type %T", res)
	}
	return wr
}

// TestCreateIncidentIdempotent: the first create opens INC…001; a second create
// with the same idempotency key dedups via correlation_id and returns the same
// number WITHOUT a second POST (08 §6a — a retry never opens a duplicate).
func TestCreateIncidentIdempotent(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	params := map[string]any{"assignment_group": "SOC-Tier3", "short_description": "Contain WIN-FILE01"}

	first := dispatch(t, b, "create_incident", params, "idem-A")
	if first.FinalOutcome != action.OutcomeSucceeded || first.PerTargetResults["SOC-Tier3"] != action.TargetOK {
		t.Fatalf("first create = %+v, want SUCCEEDED/OK", first)
	}
	if first.RawResponseRef != "INC0000001" {
		t.Errorf("created number = %q, want INC0000001", first.RawResponseRef)
	}

	second := dispatch(t, b, "create_incident", params, "idem-A")
	if second.RawResponseRef != "INC0000001" {
		t.Errorf("dedup number = %q, want the original INC0000001", second.RawResponseRef)
	}
	if m.postCount != 1 {
		t.Errorf("POST count = %d, want 1 (the retry must dedup, not re-create)", m.postCount)
	}
}

// TestProtocolParamsNeverReachServiceNow: the resolver injects action_type and
// resolved_identifier into dispatch params (protocol metadata); neither may be
// written as an incident field on create or PATCH.
func TestProtocolParamsNeverReachServiceNow(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	created := dispatch(t, b, "create_incident", map[string]any{
		"assignment_group": "SOC", "short_description": "x",
		"action_type": "ticket.create", "resolved_identifier": "SOC", // as injected by the resolver
	}, "k1")
	for _, k := range []string{"action_type", "resolved_identifier"} {
		if _, leaked := m.createBody[k]; leaked {
			t.Errorf("create body leaked protocol param %q: %+v", k, m.createBody)
		}
	}

	_ = dispatch(t, b, "add_comment", map[string]any{
		"ticket": created.RawResponseRef, "work_notes": "n",
		"action_type": "ticket.comment", "resolved_identifier": created.RawResponseRef,
	}, "k2")
	for _, k := range []string{"action_type", "resolved_identifier", "ticket"} {
		if _, leaked := m.patchBody[k]; leaked {
			t.Errorf("PATCH body leaked protocol param %q: %+v", k, m.patchBody)
		}
	}
}

// TestCommentResolvesNumber: ticket.comment targets a display number; the
// adapter resolves it to a sys_id (number→sys_id GET) then PATCHes work_notes.
func TestCommentResolvesNumber(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	created := dispatch(t, b, "create_incident", map[string]any{"assignment_group": "SOC", "short_description": "x"}, "k1")
	num := created.RawResponseRef // INC0000001

	res := dispatch(t, b, "add_comment", map[string]any{"ticket": num, "work_notes": "reimage scheduled"}, "k2")
	if res.FinalOutcome != action.OutcomeSucceeded {
		t.Fatalf("comment = %+v, want SUCCEEDED", res)
	}
	if m.patchBody["work_notes"] != "reimage scheduled" {
		t.Errorf("PATCH body = %+v, want work_notes set", m.patchBody)
	}
	if _, addressed := m.patchBody["ticket"]; addressed {
		t.Error("the addressing key 'ticket' leaked into the PATCH body")
	}
}

// TestCloseSetsStateAndCode: ticket.close stamps state 7 and a default close
// code even when the caller supplied only notes.
func TestCloseSetsStateAndCode(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	created := dispatch(t, b, "create_incident", map[string]any{"assignment_group": "SOC", "short_description": "x"}, "k1")

	res := dispatch(t, b, "close_incident", map[string]any{"ticket": created.RawResponseRef, "close_notes": "resolved"}, "k2")
	if res.FinalOutcome != action.OutcomeSucceeded {
		t.Fatalf("close = %+v, want SUCCEEDED", res)
	}
	if m.patchBody["state"] != stateClosed {
		t.Errorf("close state = %v, want %s", m.patchBody["state"], stateClosed)
	}
	if m.patchBody["close_code"] != defaultCloseCode {
		t.Errorf("close_code = %v, want the default", m.patchBody["close_code"])
	}
	if m.patchBody["close_notes"] != "resolved" {
		t.Errorf("close_notes = %v, want 'resolved'", m.patchBody["close_notes"])
	}
}

// TestTransitionAcceptsSysID: a 32-hex sys_id is used directly — no number
// lookup — and set_state writes the target state.
func TestTransitionAcceptsSysID(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	_ = dispatch(t, b, "create_incident", map[string]any{"assignment_group": "SOC", "short_description": "x"}, "k1")
	sysID := fmt.Sprintf("%032x", 1) // the first created record's sys_id

	res := dispatch(t, b, "set_state", map[string]any{"ticket": sysID, "state": "2"}, "k2")
	if res.FinalOutcome != action.OutcomeSucceeded {
		t.Fatalf("transition = %+v, want SUCCEEDED", res)
	}
	if m.patchBody["state"] != "2" {
		t.Errorf("state = %v, want 2", m.patchBody["state"])
	}
}

// TestCommentTargetNotFound: an unknown incident number resolves to nothing →
// FAIL, FATAL (08 §6c: target-not-found is definitive, never retried).
func TestCommentTargetNotFound(t *testing.T) {
	m := newSNowMock()
	b := configuredBridge(t, m.server(t).URL)
	res := dispatch(t, b, "add_comment", map[string]any{"ticket": "INC9999999", "work_notes": "x"}, "k")
	if res.FinalOutcome != action.OutcomeFailed || res.PerTargetResults["INC9999999"] != action.TargetFail {
		t.Fatalf("result = %+v, want FAILED/FAIL", res)
	}
	if res.ErrorClass != action.WriteFatal {
		t.Errorf("class = %s, want FATAL", res.ErrorClass)
	}
}

// TestAuthFailureIsFatal: bad credentials → 401 on the create → FAIL, FATAL.
func TestAuthFailureIsFatal(t *testing.T) {
	m := newSNowMock()
	b := newBridge()
	cfg, _ := json.Marshal(adapterplugin.ConfigureParams{Config: map[string]any{
		"instance_url": m.server(t).URL, "username": "admin", "password": "WRONG",
	}})
	if _, werr := b.configure(cfg); werr != nil {
		t.Fatalf("configure: %v", werr)
	}
	res := dispatch(t, b, "create_incident", map[string]any{"assignment_group": "SOC", "short_description": "x"}, "k")
	if res.FinalOutcome != action.OutcomeFailed || res.ErrorClass != action.WriteFatal {
		t.Fatalf("result = %+v, want FAILED/FATAL on 401", res)
	}
}

// TestTransportAmbiguityUnknown: the instance is unreachable → per-target
// UNKNOWN, retryable — never an inferred failure (08 §6c).
func TestTransportAmbiguityUnknown(t *testing.T) {
	m := newSNowMock()
	srv := m.server(t)
	url := srv.URL
	srv.Close() // unreachable
	b := configuredBridge(t, url)
	res := dispatch(t, b, "create_incident", map[string]any{"assignment_group": "SOC", "short_description": "x"}, "k")
	if res.PerTargetResults["SOC"] != action.TargetUnknown || res.ErrorClass != action.WriteRetryable {
		t.Fatalf("result = %+v, want UNKNOWN/RETRYABLE", res)
	}
}
