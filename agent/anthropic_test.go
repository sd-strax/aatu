package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAnthropic_Complete: the provider round-trips the request (system, tools,
// tool_result history) onto the Messages API wire shape and maps the response
// blocks back into the loop's neutral types.
func TestAnthropic_Complete(t *testing.T) {
	var got anthropicRequest
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{
		  "content":[
		    {"type":"text","text":"checking"},
		    {"type":"tool_use","id":"tu1","name":"enumerate_logons","input":{"entity":{"host":{"hostname":"H1"}}}}
		  ],
		  "stop_reason":"tool_use",
		  "usage":{"input_tokens":40,"output_tokens":12,"cache_creation_input_tokens":30,"cache_read_input_tokens":100}
		}`))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL}
	resp, err := a.Complete(context.Background(), CompleteRequest{
		System:    "sys",
		MaxTokens: 128,
		Messages: []Message{
			{Role: RoleUser, Content: []ContentBlock{TextBlock("hi")}},
			{Role: RoleAssistant, Content: []ContentBlock{{Type: BlockToolUse, ToolUseID: "t0", ToolName: "x", Input: json.RawMessage(`{}`)}}},
			{Role: RoleUser, Content: []ContentBlock{{Type: BlockToolResult, ToolUseID: "t0", Content: "r", IsError: true}}},
		},
		Tools: []ToolDef{{Name: "enumerate_logons", Description: "d", InputSchema: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if gotHeaders.Get("x-api-key") != "k" || gotHeaders.Get("anthropic-version") == "" {
		t.Errorf("auth headers missing: %v", gotHeaders)
	}
	if got.Model != DefaultAnthropicModel || got.MaxTokens != 128 {
		t.Errorf("request envelope mangled: %+v", got)
	}
	// System travels as the array form (so a cache_control breakpoint can ride it).
	if len(got.System) != 1 || got.System[0].Text != "sys" || got.System[0].Type != "text" {
		t.Errorf("system block mangled: %+v", got.System)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "enumerate_logons" {
		t.Errorf("tools mangled: %+v", got.Tools)
	}
	if len(got.Messages) != 3 {
		t.Fatalf("messages = %d; want 3", len(got.Messages))
	}
	tr := got.Messages[2].Content[0]
	if tr.Type != "tool_result" || tr.ToolUseID != "t0" || !tr.IsError {
		t.Errorf("tool_result mangled: %+v", tr)
	}

	// Prompt-cache breakpoints ride the static system+tools prefix and the last
	// message block (05 §2.7): the loop resends these every call.
	if got.System[0].CacheControl == nil || got.Tools[0].CacheControl == nil {
		t.Error("cache breakpoints missing on system/tools")
	}
	if last := got.Messages[2].Content[0]; last.CacheControl == nil {
		t.Error("cache breakpoint missing on the last message block")
	}

	if resp.StopReason != StopToolUse || len(resp.Content) != 2 {
		t.Fatalf("response mangled: %+v", resp)
	}
	tu := resp.Content[1]
	if tu.Type != BlockToolUse || tu.ToolName != "enumerate_logons" || tu.ToolUseID != "tu1" {
		t.Errorf("tool_use mapping mangled: %+v", tu)
	}
	// Usage parses, with the cache counters kept disjoint from Input.
	if resp.Usage != (Usage{Input: 40, Output: 12, CacheWrite: 30, CacheRead: 100}) {
		t.Errorf("usage mangled: %+v", resp.Usage)
	}
}

// TestAnthropic_CachingDisabled: DisableCaching omits every cache breakpoint.
func TestAnthropic_CachingDisabled(t *testing.T) {
	var got anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL, DisableCaching: true}
	if _, err := a.Complete(context.Background(), CompleteRequest{
		System: "sys", MaxTokens: 8,
		Messages: []Message{{Role: RoleUser, Content: []ContentBlock{TextBlock("hi")}}},
		Tools:    []ToolDef{{Name: "t", InputSchema: map[string]any{"type": "object"}}},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.System[0].CacheControl != nil || got.Tools[0].CacheControl != nil ||
		got.Messages[0].Content[0].CacheControl != nil {
		t.Error("DisableCaching should omit all cache breakpoints")
	}
}

// sseBody joins pre-framed SSE events for a fake streaming endpoint.
func sseBody(events ...string) string {
	var b strings.Builder
	for _, e := range events {
		b.WriteString(e)
		b.WriteString("\n\n")
	}
	return b.String()
}

// A complete happy-path stream: text in two fragments, then a tool_use whose
// input arrives as two partial_json deltas.
var streamHappyPath = sseBody(
	`event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":40,"output_tokens":1,"cache_creation_input_tokens":30,"cache_read_input_tokens":100}}}`,
	`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
	`event: ping
data: {"type":"ping"}`,
	`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chec"}}`,
	`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"king"}}`,
	`event: content_block_stop
data: {"type":"content_block_stop","index":0}`,
	`event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu1","name":"enumerate_logons","input":{}}}`,
	`event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"entity\":"}}`,
	`event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"host\":\"H1\"}}"}}`,
	`event: content_block_stop
data: {"type":"content_block_stop","index":1}`,
	`event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":12}}`,
	`event: message_stop
data: {"type":"message_stop"}`,
)

// TestAnthropic_CompleteStream: the SSE stream emits text deltas in order and
// folds into the SAME CompleteResponse the non-streaming path would return —
// text blocks assembled, tool_use input joined from partial_json, usage merged
// from message_start + message_delta (the StreamingLLM contract).
func TestAnthropic_CompleteStream(t *testing.T) {
	var got anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(streamHappyPath))
	}))
	defer srv.Close()

	var deltas []string
	a := &Anthropic{APIKey: "k", BaseURL: srv.URL}
	resp, err := a.CompleteStream(context.Background(), CompleteRequest{
		MaxTokens: 128,
		Messages:  []Message{{Role: RoleUser, Content: []ContentBlock{TextBlock("hi")}}},
	}, func(text string) { deltas = append(deltas, text) })
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}

	if !got.Stream {
		t.Error("request did not set stream:true")
	}
	if want := []string{"chec", "king"}; len(deltas) != 2 || deltas[0] != want[0] || deltas[1] != want[1] {
		t.Errorf("deltas = %q; want %q", deltas, want)
	}
	if resp.StopReason != StopToolUse || len(resp.Content) != 2 {
		t.Fatalf("response mangled: %+v", resp)
	}
	if txt := resp.Content[0]; txt.Type != BlockText || txt.Text != "checking" {
		t.Errorf("text block = %+v; want assembled 'checking'", txt)
	}
	tu := resp.Content[1]
	if tu.Type != BlockToolUse || tu.ToolUseID != "tu1" || tu.ToolName != "enumerate_logons" {
		t.Errorf("tool_use mangled: %+v", tu)
	}
	if string(tu.Input) != `{"entity":{"host":"H1"}}` {
		t.Errorf("tool input = %s; want the joined partial_json", tu.Input)
	}
	if resp.Usage != (Usage{Input: 40, Output: 12, CacheWrite: 30, CacheRead: 100}) {
		t.Errorf("usage = %+v; want message_start input + message_delta output", resp.Usage)
	}
}

// TestAnthropic_StreamRetriesBeforeFirstDelta: a 529 before any SSE bytes is
// ordinary backpressure — retried like the non-streaming path, and the
// eventual stream's deltas are emitted exactly once.
func TestAnthropic_StreamRetriesBeforeFirstDelta(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(529)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(streamHappyPath))
	}))
	defer srv.Close()

	var deltas []string
	a := &Anthropic{APIKey: "k", BaseURL: srv.URL, RetryBaseDelay: time.Millisecond}
	resp, err := a.CompleteStream(context.Background(), CompleteRequest{MaxTokens: 1},
		func(text string) { deltas = append(deltas, text) })
	if err != nil {
		t.Fatalf("CompleteStream after transient 529: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("attempts = %d; want 2", n)
	}
	if len(deltas) != 2 {
		t.Errorf("deltas emitted %d times; a retried call must not replay them", len(deltas))
	}
	if resp.StopReason != StopToolUse {
		t.Errorf("stop reason = %q", resp.StopReason)
	}
}

// TestAnthropic_StreamMidwayFailureIsTerminal: once a delta has reached the
// surface, a retry would replay already-rendered text — a stream that dies
// after first output fails without another attempt.
func TestAnthropic_StreamMidwayFailureIsTerminal(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		// One delta, then the stream ends with no message_stop (connection died).
		_, _ = w.Write([]byte(sseBody(
			`event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}`,
			`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`,
		)))
	}))
	defer srv.Close()

	var deltas []string
	a := &Anthropic{APIKey: "k", BaseURL: srv.URL, RetryBaseDelay: time.Millisecond}
	_, err := a.CompleteStream(context.Background(), CompleteRequest{MaxTokens: 1},
		func(text string) { deltas = append(deltas, text) })
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error = %v; want the truncated-stream failure surfaced", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("attempts = %d; a mid-stream failure after output must not retry", n)
	}
	if len(deltas) != 1 || deltas[0] != "partial" {
		t.Errorf("deltas = %q; want the one fragment that arrived", deltas)
	}
}

// TestAnthropic_StreamErrorEventBeforeOutputRetries: a provider error event
// that arrives before any text (e.g. overloaded_error at stream start) is
// still safe to retry — nothing has been rendered.
func TestAnthropic_StreamErrorEventBeforeOutputRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(sseBody(
				`event: error
data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
			)))
			return
		}
		_, _ = w.Write([]byte(streamHappyPath))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL, RetryBaseDelay: time.Millisecond}
	resp, err := a.CompleteStream(context.Background(), CompleteRequest{MaxTokens: 1}, func(string) {})
	if err != nil {
		t.Fatalf("CompleteStream after pre-output error event: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("attempts = %d; want 2 (error event before output is retryable)", n)
	}
	if resp.StopReason != StopToolUse {
		t.Errorf("stop reason = %q", resp.StopReason)
	}
}

// TestAnthropic_APIError: a non-200 with the API error envelope surfaces the
// provider's message. A 400 is a request defect — it must NOT be retried.
func TestAnthropic_APIError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens required"}}`))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL}
	_, err := a.Complete(context.Background(), CompleteRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "invalid_request_error") {
		t.Errorf("error = %v; want the provider message surfaced", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("400 was attempted %d times; a request defect must not be retried", n)
	}
}

// TestAnthropic_RetriesOverload: a 529 overloaded_error is transient — the
// client rides it out with backoff and succeeds once the provider recovers,
// firing OnRetry for each wait.
func TestAnthropic_RetriesOverload(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(529)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()

	var retries atomic.Int32
	a := &Anthropic{
		APIKey:         "k",
		BaseURL:        srv.URL,
		RetryBaseDelay: time.Millisecond, // keep the test fast
		OnRetry:        func(int, time.Duration, error) { retries.Add(1) },
	}
	resp, err := a.Complete(context.Background(), CompleteRequest{MaxTokens: 1})
	if err != nil {
		t.Fatalf("Complete after transient 529s: %v", err)
	}
	if resp.StopReason != StopEndTurn || len(resp.Content) != 1 {
		t.Errorf("response after recovery mangled: %+v", resp)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("attempts = %d; want 3 (two 529s + success)", n)
	}
	if n := retries.Load(); n != 2 {
		t.Errorf("OnRetry fired %d times; want 2", n)
	}
}

// TestAnthropic_RetryBudgetExhausted: sustained overload past the budget
// surfaces the last error rather than looping forever.
func TestAnthropic_RetryBudgetExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(529)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL, MaxRetries: 2, RetryBaseDelay: time.Millisecond}
	_, err := a.Complete(context.Background(), CompleteRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "overloaded_error") {
		t.Errorf("error = %v; want the overloaded_error surfaced after the budget", err)
	}
	if n := calls.Load(); n != 3 { // 1 initial + 2 retries
		t.Errorf("attempts = %d; want 3 (initial + MaxRetries)", n)
	}
}
