package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scriptedLLM replays a fixed sequence of completions and records what it was
// asked.
type scriptedLLM struct {
	script   []CompleteResponse
	requests []CompleteRequest
}

func (s *scriptedLLM) Complete(_ context.Context, req CompleteRequest) (CompleteResponse, error) {
	s.requests = append(s.requests, req)
	if len(s.script) == 0 {
		return CompleteResponse{Content: []ContentBlock{TextBlock("(script exhausted)")}, StopReason: StopEndTurn}, nil
	}
	next := s.script[0]
	s.script = s.script[1:]
	return next, nil
}

// recordedCall is one request the fake backend saw.
type recordedCall struct {
	Method string
	Path   string
	Token  string
	Body   []byte
}

// fakeBackend is an httptest server standing in for the reckon backend. It
// records every call and serves canned responses for the routes the loop uses.
// override, when set, intercepts matching paths before the canned routes.
type fakeBackend struct {
	srv      *httptest.Server
	calls    []recordedCall
	override func(w http.ResponseWriter, r *http.Request) bool // handled?
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	f := &fakeBackend{}
	mux := http.NewServeMux()

	record := func(r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.calls = append(f.calls, recordedCall{
			Method: r.Method,
			Path:   r.URL.Path,
			Token:  strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
			Body:   body,
		})
	}

	mux.HandleFunc("/api/investigations/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if strings.HasSuffix(r.URL.Path, "/hypotheses") {
			_, _ = w.Write([]byte(`{"hypotheses":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(Investigation{AggregateID: "inv-1", Title: "INV", Status: "ACTIVE"})
	})
	mux.HandleFunc("/api/capabilities", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte(`{"capabilities":[
		  {"descriptor":{"verb":"enumerate_logons","intent":"List logons.","inputs":[
		     {"name":"target","type":"entity","required":true,"desc":"user or host"},
		     {"name":"window","type":"time_window","required":false},
		     {"name":"outcome","type":"enum","required":false,"desc":"SUCCESS|FAILURE|ALL"}],
		    "output":"list<observed_data>"},"status":"available","bindings":1},
		  {"descriptor":{"verb":"get_process_ancestry","intent":"Walk ancestry.","inputs":[],"output":"x"},"status":"degraded","bindings":1},
		  {"descriptor":{"verb":"search_alerts","intent":"Search alerts.","inputs":[],"output":"x"},"status":"unavailable","bindings":0}
		]}`))
	})
	mux.HandleFunc("/api/capability/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte(`{"verb":"enumerate_logons","coverage":"COMPLETE","observed_data_refs":["observed-data--od1"],"entity_refs":["user-account--u1"]}`))
	})
	mux.HandleFunc("/api/interpretations", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		var body InterpretationRequest
		raw := f.calls[len(f.calls)-1].Body
		_ = json.Unmarshal(raw, &body)
		resp := InterpretationResponse{InterpretationID: "interp-1", SequenceNo: 7}
		if body.Hypothesis != nil {
			resp.NodeID = "x-hypothesis--h1"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/actions", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_ = json.NewEncoder(w).Encode(ActionResponse{ActionID: "act-1", Tier: "T2", Status: "PENDING_MANUAL", Mode: "MANUAL"})
	})
	mux.HandleFunc("/api/knowledge/recall_sops", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte(`{"results":[],"coverage":"EMPTY"}`))
	})

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.override != nil && f.override(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBackend) client() *Client { return NewClient(f.srv.URL, "AGENT_TOKEN", "HUMAN_TOKEN") }

func (f *fakeBackend) callsTo(path string) []recordedCall {
	var out []recordedCall
	for _, c := range f.calls {
		if c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func toolUse(id, name, input string) ContentBlock {
	return ContentBlock{Type: BlockToolUse, ToolUseID: id, ToolName: name, Input: json.RawMessage(input)}
}

// TestSession_ToolAssembly: available verbs become tools, degraded/unavailable
// are trimmed, intrinsic tools are present, and the system prompt carries the
// investigation + degraded-verb context.
func TestSession_ToolAssembly(t *testing.T) {
	f := newFakeBackend(t)
	s, err := NewSession(context.Background(), Config{
		Backend: f.client(), LLM: &scriptedLLM{}, InvestigationID: "inv-1",
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	names := map[string]bool{}
	for _, d := range s.Tools() {
		names[d.Name] = true
	}
	for _, want := range []string{"enumerate_logons", ToolRecallSOPs, ToolProposeHypothesis,
		ToolRecordPrediction, ToolEvaluateHypothesis, ToolRecordPredictionOutcome, ToolRequestAction} {
		if !names[want] {
			t.Errorf("tool %q missing from set %v", want, names)
		}
	}
	for _, absent := range []string{"get_process_ancestry", "search_alerts", "list_capabilities"} {
		if names[absent] {
			t.Errorf("tool %q should be trimmed (degraded/unavailable)", absent)
		}
	}
	if !strings.Contains(s.system, "INV") || !strings.Contains(s.system, "get_process_ancestry") {
		t.Error("system prompt missing investigation title or degraded-verb note")
	}
}

// TestSession_Turn: a full turn — capability call, hypothesis proposal, action
// request, final text — dispatches each tool with the AGENT token, feeds
// results back, and commits the transcript + tool-call log as one turn-summary
// interpretation.
func TestSession_Turn(t *testing.T) {
	f := newFakeBackend(t)
	llm := &scriptedLLM{script: []CompleteResponse{
		{StopReason: StopToolUse, Content: []ContentBlock{
			TextBlock("Checking logons."),
			toolUse("t1", "enumerate_logons", `{"entity":{"host":{"hostname":"H1"}},"outcome":"SUCCESS"}`),
		}},
		{StopReason: StopToolUse, Content: []ContentBlock{
			toolUse("t2", ToolProposeHypothesis, `{"statement":"RDP lateral movement to H1","rationale":"successful remote logons cite observed-data--od1","labels":["T1021.001"]}`),
		}},
		{StopReason: StopToolUse, Content: []ContentBlock{
			toolUse("t3", ToolRequestAction, `{"action_type":"host.isolate","targets":[{"entity_ref":"x-host--1","resolved_identifier":"H1"}],"rationale":"contain lateral movement","evidence_refs":["observed-data--od1"]}`),
		}},
		{StopReason: StopEndTurn, Content: []ContentBlock{
			TextBlock("I found successful RDP logons, proposed a hypothesis, and requested isolation pending your approval."),
		}},
	}}

	s, err := NewSession(context.Background(), Config{Backend: f.client(), LLM: llm, InvestigationID: "inv-1"})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	res, err := s.Turn(context.Background(), "Is H1 being laterally moved to?")
	if err != nil {
		t.Fatalf("Turn: %v", err)
	}

	if res.ToolRounds != 3 {
		t.Errorf("rounds = %d; want 3", res.ToolRounds)
	}
	if !strings.Contains(res.Text, "isolation") {
		t.Errorf("final text lost: %q", res.Text)
	}
	if res.InterpretationID != "interp-1" {
		t.Errorf("turn not committed: %+v", res)
	}
	if len(res.PendingActions) != 1 || res.PendingActions[0].Status != "PENDING_MANUAL" {
		t.Errorf("pending actions = %+v; want the PENDING_MANUAL isolate", res.PendingActions)
	}

	// Every loop-driven call used the agent token.
	for _, c := range f.calls {
		if c.Token != "AGENT_TOKEN" {
			t.Errorf("%s %s used token %q; the loop must always act as the delegate", c.Method, c.Path, c.Token)
		}
	}

	// The capability dispatch carried the entity and the extra param.
	invokes := f.callsTo("/api/capability/enumerate_logons")
	if len(invokes) != 1 {
		t.Fatalf("capability invocations = %d; want 1", len(invokes))
	}
	var call InvokeInput
	_ = json.Unmarshal(invokes[0].Body, &call)
	host, _ := call.Entity["host"].(map[string]any)
	if host["hostname"] != "H1" || call.Extra["outcome"] != "SUCCESS" {
		t.Errorf("invoke body mangled: %s", invokes[0].Body)
	}

	// Three interpretations: hypothesis, (action rides /api/actions), turn summary.
	interps := f.callsTo("/api/interpretations")
	if len(interps) != 2 {
		t.Fatalf("interpretation posts = %d; want 2 (hypothesis + turn summary)", len(interps))
	}
	var hyp InterpretationRequest
	_ = json.Unmarshal(interps[0].Body, &hyp)
	if hyp.InterpretationType != "hypothesis" || hyp.Hypothesis == nil || hyp.Hypothesis.Labels[0] != "T1021.001" {
		t.Errorf("hypothesis interpretation mangled: %+v", hyp)
	}
	var summary InterpretationRequest
	_ = json.Unmarshal(interps[1].Body, &summary)
	if summary.Transcript == nil || summary.Transcript.Body == "" {
		t.Fatal("turn summary carries no transcript")
	}
	for _, want := range []string{"[user]", "enumerate_logons", ToolProposeHypothesis, ToolRequestAction, "[assistant]"} {
		if !strings.Contains(summary.Transcript.Body, want) {
			t.Errorf("transcript missing %q", want)
		}
	}
	if len(summary.ToolCalls) != 3 {
		t.Errorf("tool-call log = %d entries; want 3", len(summary.ToolCalls))
	}
	if summary.Rationale == "" || len([]rune(summary.Rationale)) > maxRationaleRunes {
		t.Errorf("rationale bound violated: %d runes", len([]rune(summary.Rationale)))
	}

	// The model received the tool results (hypothesis ref surfaced back).
	last := llm.requests[len(llm.requests)-1]
	var sawRef bool
	for _, m := range last.Messages {
		for _, blk := range m.Content {
			if blk.Type == BlockToolResult && strings.Contains(blk.Content, "x-hypothesis--h1") {
				sawRef = true
			}
		}
	}
	if !sawRef {
		t.Error("hypothesis ref never fed back to the model")
	}
}

// TestSession_BackendRejectionFeedsModel: a 4xx from the backend becomes an
// isError tool result (the engine's explanation reaches the model); the turn
// continues rather than aborting.
func TestSession_BackendRejectionFeedsModel(t *testing.T) {
	f := newFakeBackend(t)
	// Override /api/actions with a Gate-2-style denial.
	f.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/actions" {
			return false
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"baseline DENY: AI-delegated T3 cannot auto-approve"}`))
		return true
	}

	llm := &scriptedLLM{script: []CompleteResponse{
		{StopReason: StopToolUse, Content: []ContentBlock{
			toolUse("t1", ToolRequestAction, `{"action_type":"tenant.wipe","targets":[{"entity_ref":"x","resolved_identifier":"all"}],"rationale":"nope"}`),
		}},
		{StopReason: StopEndTurn, Content: []ContentBlock{TextBlock("That action was denied by policy; here is why…")}},
	}}
	s, err := NewSession(context.Background(), Config{Backend: f.client(), LLM: llm, InvestigationID: "inv-1"})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	res, err := s.Turn(context.Background(), "wipe everything")
	if err != nil {
		t.Fatalf("Turn should survive a tool rejection: %v", err)
	}
	if len(res.PendingActions) != 0 {
		t.Error("denied action must not surface as pending")
	}

	// The denial text reached the model as an error tool result.
	last := llm.requests[len(llm.requests)-1]
	var sawDenial bool
	for _, m := range last.Messages {
		for _, blk := range m.Content {
			if blk.Type == BlockToolResult && blk.IsError && strings.Contains(blk.Content, "baseline DENY") {
				sawDenial = true
			}
		}
	}
	if !sawDenial {
		t.Error("denial did not reach the model as an isError tool result")
	}
}

// TestSession_ToolBudget: a model that never stops issuing tool calls is cut
// off at MaxToolRounds and the turn still commits.
func TestSession_ToolBudget(t *testing.T) {
	f := newFakeBackend(t)
	looping := make([]CompleteResponse, 0, 10)
	for i := 0; i < 10; i++ {
		looping = append(looping, CompleteResponse{StopReason: StopToolUse, Content: []ContentBlock{
			toolUse("t", ToolRecallSOPs, `{"query":"again"}`),
		}})
	}
	llm := &scriptedLLM{script: looping}
	s, err := NewSession(context.Background(), Config{
		Backend: f.client(), LLM: llm, InvestigationID: "inv-1", MaxToolRounds: 3,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	res, err := s.Turn(context.Background(), "loop forever")
	if err != nil {
		t.Fatalf("Turn: %v", err)
	}
	if res.ToolRounds > 3+1 {
		t.Errorf("rounds = %d; budget did not bind", res.ToolRounds)
	}
	if res.InterpretationID == "" {
		t.Error("budget-exhausted turn was not committed")
	}
}

// TestClipRunes: the rationale clip is rune-safe.
func TestClipRunes(t *testing.T) {
	if got := clipRunes("héllo wörld", 5); len([]rune(got)) != 5 {
		t.Errorf("clip = %q (%d runes)", got, len([]rune(got)))
	}
	if got := clipRunes("short", 500); got != "short" {
		t.Errorf("clip mangled short string: %q", got)
	}
}
