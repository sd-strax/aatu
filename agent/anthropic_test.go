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
		  "stop_reason":"tool_use"
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
	if got.Model != DefaultAnthropicModel || got.System != "sys" || got.MaxTokens != 128 {
		t.Errorf("request envelope mangled: %+v", got)
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

	if resp.StopReason != StopToolUse || len(resp.Content) != 2 {
		t.Fatalf("response mangled: %+v", resp)
	}
	tu := resp.Content[1]
	if tu.Type != BlockToolUse || tu.ToolName != "enumerate_logons" || tu.ToolUseID != "tu1" {
		t.Errorf("tool_use mapping mangled: %+v", tu)
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
