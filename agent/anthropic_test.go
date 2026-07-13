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
// provider's message.
func TestAnthropic_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens required"}}`))
	}))
	defer srv.Close()

	a := &Anthropic{APIKey: "k", BaseURL: srv.URL}
	_, err := a.Complete(context.Background(), CompleteRequest{MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "invalid_request_error") {
		t.Errorf("error = %v; want the provider message surfaced", err)
	}
}
