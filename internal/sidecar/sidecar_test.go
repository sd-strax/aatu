package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/server"
)

// TestFraming_RoundTrip: a written frame reads back byte-identical, and extra
// headers (vscode-jsonrpc sends Content-Type) are tolerated.
func TestFraming_RoundTrip(t *testing.T) {
	var buf strings.Builder
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	// Splice in an extra header the way vscode-jsonrpc does.
	framed := strings.Replace(buf.String(), "\r\n\r\n",
		"\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n", 1)

	got, err := readFrame(bufio.NewReader(strings.NewReader(framed)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("round trip = %q; want %q", got, payload)
	}

	// A frame with no Content-Length is a protocol error, not a hang.
	if _, err := readFrame(bufio.NewReader(strings.NewReader("Content-Type: x\r\n\r\n"))); err == nil {
		t.Error("frame without Content-Length did not error")
	}
}

// --- test client over pipes --------------------------------------------------

// testClient speaks the raw framed protocol from the test side: requests get
// correlated responses; the server's getToken callbacks are answered with
// per-kind tokens; notifications are collected.
type testClient struct {
	t *testing.T
	w io.Writer

	mu       sync.Mutex
	nextID   int64
	pending  map[int64]chan *message
	notes    []message
	tokenReq []getTokenParams
}

func newTestClient(t *testing.T, r io.Reader, w io.Writer) *testClient {
	c := &testClient{t: t, w: w, pending: map[int64]chan *message{}}
	go c.pump(r)
	return c
}

func (c *testClient) pump(r io.Reader) {
	br := bufio.NewReader(r)
	for {
		payload, err := readFrame(br)
		if err != nil {
			return
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			c.t.Errorf("client: bad frame %s: %v", payload, err)
			return
		}
		switch {
		case msg.Method == "getToken" && msg.ID != nil:
			var p getTokenParams
			_ = json.Unmarshal(msg.Params, &p)
			c.mu.Lock()
			c.tokenReq = append(c.tokenReq, p)
			c.mu.Unlock()
			result, _ := json.Marshal(getTokenResult{Token: "tok-" + p.Kind})
			c.send(&message{JSONRPC: "2.0", ID: msg.ID, Result: result})
		case msg.Method != "": // notification
			c.mu.Lock()
			c.notes = append(c.notes, msg)
			c.mu.Unlock()
		case msg.ID != nil: // response to one of ours
			var id int64
			_ = json.Unmarshal(*msg.ID, &id)
			c.mu.Lock()
			ch := c.pending[id]
			delete(c.pending, id)
			c.mu.Unlock()
			if ch != nil {
				ch <- &msg
			}
		}
	}
}

func (c *testClient) send(msg *message) {
	payload, err := json.Marshal(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFrame(c.w, payload); err != nil {
		c.t.Errorf("client write: %v", err)
	}
}

// call issues a request and waits for its response (10s guard).
func (c *testClient) call(method string, params any) *message {
	c.t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	idRaw := json.RawMessage(fmt.Sprintf("%d", id))
	c.send(&message{JSONRPC: "2.0", ID: &idRaw, Method: method, Params: raw})
	select {
	case resp := <-ch:
		return resp
	case <-time.After(10 * time.Second):
		c.t.Fatalf("no response to %s within 10s", method)
		return nil
	}
}

func (c *testClient) notifications(method string) []message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []message
	for _, n := range c.notes {
		if n.Method == method {
			out = append(out, n)
		}
	}
	return out
}

// --- fake backend ------------------------------------------------------------

// fakeBackend serves the minimal API surface a session touches, asserting the
// delegate token on every agent-path call (the two-token discipline).
func fakeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"overall": "ok", "api_version": server.APIVersion})
	})
	requireDelegate := func(r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-delegate" {
			t.Errorf("%s %s carried %q; want the delegate token", r.Method, r.URL.Path, got)
		}
	}
	mux.HandleFunc("/api/investigations/inv-1", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"aggregate_id": "inv-1", "title": "RDP sweep", "status": "ACTIVE"})
	})
	mux.HandleFunc("/api/capabilities", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"capabilities": []map[string]any{{
			"descriptor": map[string]any{
				"verb": "enumerate_logons", "intent": "list logons",
				"inputs": []map[string]any{{"name": "target", "type": "entity", "required": true}},
				"output": "list<observed_data>",
			},
			"status": "available",
		}}})
	})
	mux.HandleFunc("/api/investigations/inv-1/hypotheses", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"hypotheses": []any{}})
	})
	mux.HandleFunc("/api/action-types", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "action layer off", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/api/capability/enumerate_logons", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"verb": "enumerate_logons", "coverage": "COMPLETE", "events": []any{}})
	})
	mux.HandleFunc("/api/interpretations", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"interpretation_id": "interp-42"})
	})
	mux.HandleFunc("/api/investigations/inv-1/actions", func(w http.ResponseWriter, r *http.Request) {
		requireDelegate(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"actions": []map[string]any{{
			"action_id": "act-9", "action_type": "ioc.block", "tier": "T2", "status": "REQUESTED",
			"targets": []map[string]any{{"entity_ref": "ipv4-addr--x", "resolved_identifier": "10.0.0.9"}},
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// scriptLLM returns tool_use on the first call, end_turn text on the second.
type scriptLLM struct {
	mu    sync.Mutex
	calls int
	block chan struct{} // when set, the SECOND call parks until ctx cancel
}

func (l *scriptLLM) Complete(ctx context.Context, _ agent.CompleteRequest) (agent.CompleteResponse, error) {
	l.mu.Lock()
	l.calls++
	n := l.calls
	l.mu.Unlock()
	if n == 1 {
		return agent.CompleteResponse{
			StopReason: agent.StopToolUse,
			Content: []agent.ContentBlock{
				agent.TextBlock("checking logons"),
				{Type: agent.BlockToolUse, ToolUseID: "tu-1", ToolName: "enumerate_logons",
					Input: json.RawMessage(`{"target":{"host":{"hostname":"h1"}}}`)},
			},
			Usage: agent.Usage{Input: 100, Output: 20},
		}, nil
	}
	if l.block != nil {
		<-ctx.Done()
		return agent.CompleteResponse{}, ctx.Err()
	}
	return agent.CompleteResponse{
		StopReason: agent.StopEndTurn,
		Content:    []agent.ContentBlock{agent.TextBlock("no anomalous logons found")},
		Usage:      agent.Usage{Input: 150, Output: 30},
	}, nil
}

// startSidecar wires Serve over pipes and returns the test client.
func startSidecar(t *testing.T, llm agent.LLM) *testClient {
	t.Helper()
	c2sRead, c2sWrite := io.Pipe()
	s2cRead, s2cWrite := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, c2sRead, s2cWrite, Options{
			ServerVersion: "test",
			NewLLM:        func(_, _ string) agent.LLM { return llm },
		})
	}()
	t.Cleanup(func() {
		cancel()
		_ = c2sWrite.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return on shutdown")
		}
	})
	return newTestClient(t, s2cRead, c2sWrite)
}

func initParams(backendURL string) initializeParams {
	return initializeParams{
		ProtocolVersion: ProtocolVersion,
		BackendURL:      backendURL,
		Model:           "test-model",
		AnthropicAPIKey: "sk-test",
	}
}

// TestServe_FullFlow: initialize (both handshakes) → createSession (tools from
// the live catalog) → turn (tool round + commit + pending actions), with the
// getToken callback supplying the delegate token and progress notifications
// observed — the whole §4/§5 contract in one pass.
func TestServe_FullFlow(t *testing.T) {
	backend := fakeBackend(t)
	c := startSidecar(t, &scriptLLM{})

	// initialize
	resp := c.call("initialize", initParams(backend.URL))
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	var ini initializeResult
	if err := json.Unmarshal(resp.Result, &ini); err != nil {
		t.Fatal(err)
	}
	if ini.ProtocolVersion != ProtocolVersion || ini.BackendAPIVersion != server.APIVersion {
		t.Errorf("handshake = %+v; want protocol v%d api v%d", ini, ProtocolVersion, server.APIVersion)
	}

	// createSession
	resp = c.call("createSession", createSessionParams{InvestigationID: "inv-1"})
	if resp.Error != nil {
		t.Fatalf("createSession error: %+v", resp.Error)
	}
	var cs createSessionResult
	if err := json.Unmarshal(resp.Result, &cs); err != nil {
		t.Fatal(err)
	}
	if cs.SessionID == "" || len(cs.Tools) == 0 {
		t.Fatalf("createSession = %+v; want session id + tools", cs)
	}
	hasVerb := false
	for _, name := range cs.Tools {
		if name == "enumerate_logons" {
			hasVerb = true
		}
	}
	if !hasVerb {
		t.Errorf("tools %v missing the catalog verb", cs.Tools)
	}

	// turn
	resp = c.call("turn", turnParams{SessionID: cs.SessionID, Text: "any odd logons on h1?"})
	if resp.Error != nil {
		t.Fatalf("turn error: %+v", resp.Error)
	}
	var tr turnResult
	if err := json.Unmarshal(resp.Result, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.Error != "" {
		t.Fatalf("turn carried error %q", tr.Error)
	}
	if !strings.Contains(tr.Text, "no anomalous logons") {
		t.Errorf("turn text = %q", tr.Text)
	}
	if tr.InterpretationID != "interp-42" {
		t.Errorf("interpretation id = %q; want interp-42 (commit did not ride)", tr.InterpretationID)
	}
	if tr.ToolRounds != 1 {
		t.Errorf("tool rounds = %d; want 1", tr.ToolRounds)
	}
	if tr.Usage.Input != 250 || tr.Usage.Output != 50 {
		t.Errorf("usage = %+v; want summed 250/50", tr.Usage)
	}
	// The pending action from the durable queue rides the result for the
	// approval UI, with the PendingLabel vocabulary.
	if len(tr.PendingActions) != 1 || tr.PendingActions[0].ActionID != "act-9" ||
		tr.PendingActions[0].Status != "PENDING_MANUAL" || tr.PendingActions[0].Targets[0] != "10.0.0.9" {
		t.Errorf("pending actions = %+v", tr.PendingActions)
	}

	// Progress notifications observed: the tool round and the final text.
	if n := c.notifications("turn/tool_call"); len(n) != 1 {
		t.Errorf("turn/tool_call notifications = %d; want 1", len(n))
	}
	if n := c.notifications("turn/tool_result"); len(n) != 1 {
		t.Errorf("turn/tool_result notifications = %d; want 1", len(n))
	} else {
		// The ticker fields are distilled from the FULL payload pre-clip: an
		// honest "COMPLETE · 0 events" must arrive structurally, not by the
		// client parsing (possibly clipped) content.
		var note turnToolResultNote
		if err := json.Unmarshal(n[0].Params, &note); err != nil {
			t.Fatal(err)
		}
		if note.Coverage != "COMPLETE" || note.EventCount == nil || *note.EventCount != 0 {
			t.Errorf("tool_result note = coverage %q, count %v; want COMPLETE with explicit 0", note.Coverage, note.EventCount)
		}
	}
	if n := c.notifications("turn/text"); len(n) < 1 {
		t.Error("no turn/text notifications")
	}

	// The token handoff asked for delegate tokens (the loop's calls).
	c.mu.Lock()
	sawDelegate := false
	for _, req := range c.tokenReq {
		if req.Kind == "delegate" {
			sawDelegate = true
		}
	}
	c.mu.Unlock()
	if !sawDelegate {
		t.Error("getToken was never asked for a delegate token")
	}

	// shutdown: responds, then Serve exits (asserted in cleanup).
	if resp := c.call("shutdown", struct{}{}); resp.Error != nil {
		t.Errorf("shutdown error: %+v", resp.Error)
	}
}

// TestServe_ResponseSurvivesHalfClose: a client that sends its last request
// and immediately closes stdin still gets the response — a clean EOF waits for
// in-flight handlers to flush instead of abandoning them (the one-shot CLI
// pattern, and the regression that motivated conn.waitDispatches).
func TestServe_ResponseSurvivesHalfClose(t *testing.T) {
	c2sRead, c2sWrite := io.Pipe()
	s2cRead, s2cWrite := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), c2sRead, s2cWrite, Options{
			NewLLM: func(_, _ string) agent.LLM { return &scriptLLM{} },
		})
	}()

	// One bad-version initialize, then half-close before reading anything.
	raw, _ := json.Marshal(initializeParams{ProtocolVersion: 99})
	id := json.RawMessage("1")
	payload, _ := json.Marshal(&message{JSONRPC: "2.0", ID: &id, Method: "initialize", Params: raw})
	if err := writeFrame(c2sWrite, payload); err != nil {
		t.Fatal(err)
	}
	_ = c2sWrite.Close()

	respCh := make(chan *message, 1)
	go func() {
		frame, err := readFrame(bufio.NewReader(s2cRead))
		if err != nil {
			return
		}
		var msg message
		_ = json.Unmarshal(frame, &msg)
		respCh <- &msg
	}()
	select {
	case resp := <-respCh:
		if resp.Error == nil || !strings.Contains(resp.Error.Message, "v99") {
			t.Errorf("response after half-close = %+v; want the version diagnostic", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response after half-close — the dispatch was abandoned on EOF")
	}
	if err := <-done; err != nil {
		t.Errorf("Serve returned %v; want nil on clean EOF", err)
	}
}

// TestServe_ProtocolVersionMismatch: the stdio handshake fails closed with a
// diagnostic naming both versions.
func TestServe_ProtocolVersionMismatch(t *testing.T) {
	backend := fakeBackend(t)
	c := startSidecar(t, &scriptLLM{})
	p := initParams(backend.URL)
	p.ProtocolVersion = 99
	resp := c.call("initialize", p)
	if resp.Error == nil {
		t.Fatal("initialize with protocol v99 succeeded")
	}
	if !strings.Contains(resp.Error.Message, "v99") || !strings.Contains(resp.Error.Message, "v1") {
		t.Errorf("diagnostic %q does not name both versions", resp.Error.Message)
	}
}

// TestServe_BackendAPIVersionMismatch: the sidecar↔backend handshake fails
// closed when the backend speaks a different API contract.
func TestServe_BackendAPIVersionMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"overall": "ok", "api_version": 999})
	}))
	t.Cleanup(srv.Close)
	c := startSidecar(t, &scriptLLM{})
	resp := c.call("initialize", initParams(srv.URL))
	if resp.Error == nil {
		t.Fatal("initialize against api v999 succeeded")
	}
	if !strings.Contains(resp.Error.Message, "999") {
		t.Errorf("diagnostic %q does not name the backend version", resp.Error.Message)
	}
}

// TestServe_UnknownSession: turn/cancel against a session id that does not
// exist is a coded invalid-params error, not a crash or hang.
func TestServe_UnknownSession(t *testing.T) {
	backend := fakeBackend(t)
	c := startSidecar(t, &scriptLLM{})
	if resp := c.call("initialize", initParams(backend.URL)); resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}
	resp := c.call("turn", turnParams{SessionID: "nope", Text: "hi"})
	if resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Errorf("turn on unknown session = %+v; want invalid-params error", resp.Error)
	}
}

// TestServe_CancelAbortsTurn: cancel while a turn is parked in the model call
// unblocks it; the turn response surfaces the partial result with the
// cancellation error rather than hanging (the §4 cancel contract).
func TestServe_CancelAbortsTurn(t *testing.T) {
	backend := fakeBackend(t)
	llm := &scriptLLM{block: make(chan struct{})}
	c := startSidecar(t, llm)

	if resp := c.call("initialize", initParams(backend.URL)); resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}
	resp := c.call("createSession", createSessionParams{InvestigationID: "inv-1"})
	if resp.Error != nil {
		t.Fatalf("createSession: %+v", resp.Error)
	}
	var cs createSessionResult
	_ = json.Unmarshal(resp.Result, &cs)

	// Fire the turn without waiting, then cancel once the model call is parked
	// (second Complete call blocks; the first round's notifications tell us
	// it got there).
	turnDone := make(chan *message, 1)
	go func() { turnDone <- c.call("turn", turnParams{SessionID: cs.SessionID, Text: "go"}) }()
	deadline := time.After(5 * time.Second)
	for len(c.notifications("turn/tool_result")) == 0 {
		select {
		case <-deadline:
			t.Fatal("turn never reached the tool round")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if resp := c.call("cancel", cancelParams{SessionID: cs.SessionID}); resp.Error != nil {
		t.Fatalf("cancel: %+v", resp.Error)
	}

	select {
	case resp := <-turnDone:
		if resp.Error != nil {
			// Acceptable only as the coded cancellation.
			if resp.Error.Code != codeCancelled {
				t.Errorf("turn error = %+v; want cancelled", resp.Error)
			}
			return
		}
		var tr turnResult
		_ = json.Unmarshal(resp.Result, &tr)
		if tr.Error == "" || !strings.Contains(tr.Error, "context canceled") {
			t.Errorf("turn result after cancel = %+v; want the cancellation surfaced", tr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("turn did not return after cancel")
	}
}
