package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultAnthropicModel is the v0 default for the interactive loop. Overridable
// per session — the loop treats model choice as configuration, not code.
const DefaultAnthropicModel = "claude-sonnet-4-6"

const (
	anthropicBaseURL = "https://api.anthropic.com"
	anthropicVersion = "2023-06-01"
)

// Anthropic implements LLM over the Anthropic Messages API with the analyst's
// own key (BYOK, 05 §2.7): the key lives in this client-side process and is
// sent only to the provider — never to the reckon backend.
type Anthropic struct {
	APIKey  string
	Model   string       // defaults to DefaultAnthropicModel
	BaseURL string       // defaults to the public API; overridable for tests
	HTTP    *http.Client // defaults to a 300s-timeout client (long completions)
}

// Messages API wire shapes (only the fields the loop uses).

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
}

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

type anthropicMessage struct {
	Role    string           `json:"role"`
	Content []anthropicBlock `json:"content"`
}

type anthropicBlock struct {
	Type string `json:"type"`

	// text
	Text string `json:"text,omitempty"`

	// tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
}

type anthropicResponse struct {
	Content    []anthropicBlock `json:"content"`
	StopReason string           `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Complete runs one non-streaming Messages call. Streaming is an E.4 polish —
// the loop's contract does not change.
func (a *Anthropic) Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error) {
	if a.APIKey == "" {
		return CompleteResponse{}, fmt.Errorf("anthropic: no API key (set ANTHROPIC_API_KEY)")
	}
	model := a.Model
	if model == "" {
		model = DefaultAnthropicModel
	}
	base := a.BaseURL
	if base == "" {
		base = anthropicBaseURL
	}
	httpc := a.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 300 * time.Second}
	}

	wire := anthropicRequest{
		Model:     model,
		MaxTokens: req.MaxTokens,
		System:    req.System,
		Messages:  toAnthropicMessages(req.Messages),
	}
	for _, t := range req.Tools {
		// ToolDef and anthropicTool share field shape (tags differ, which
		// conversion ignores) — keep them in lockstep with a direct conversion.
		wire.Tools = append(wire.Tools, anthropicTool(t))
	}

	raw, err := json.Marshal(wire)
	if err != nil {
		return CompleteResponse{}, fmt.Errorf("anthropic: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(raw))
	if err != nil {
		return CompleteResponse{}, err
	}
	httpReq.Header.Set("x-api-key", a.APIKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := httpc.Do(httpReq)
	if err != nil {
		return CompleteResponse{}, fmt.Errorf("anthropic: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return CompleteResponse{}, fmt.Errorf("anthropic: read response: %w", err)
	}

	var out anthropicResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return CompleteResponse{}, fmt.Errorf("anthropic: decode (%d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if out.Error != nil {
			msg = out.Error.Type + ": " + out.Error.Message
		}
		return CompleteResponse{}, fmt.Errorf("anthropic: %d %s", resp.StatusCode, msg)
	}

	res := CompleteResponse{StopReason: out.StopReason}
	for _, blk := range out.Content {
		switch blk.Type {
		case "text":
			res.Content = append(res.Content, ContentBlock{Type: BlockText, Text: blk.Text})
		case "tool_use":
			res.Content = append(res.Content, ContentBlock{
				Type: BlockToolUse, ToolUseID: blk.ID, ToolName: blk.Name, Input: blk.Input,
			})
		}
	}
	return res, nil
}

// toAnthropicMessages converts the loop's messages to the wire shape.
func toAnthropicMessages(msgs []Message) []anthropicMessage {
	out := make([]anthropicMessage, 0, len(msgs))
	for _, m := range msgs {
		wm := anthropicMessage{Role: string(m.Role)}
		for _, blk := range m.Content {
			switch blk.Type {
			case BlockText:
				wm.Content = append(wm.Content, anthropicBlock{Type: "text", Text: blk.Text})
			case BlockToolUse:
				wm.Content = append(wm.Content, anthropicBlock{
					Type: "tool_use", ID: blk.ToolUseID, Name: blk.ToolName, Input: blk.Input,
				})
			case BlockToolResult:
				wm.Content = append(wm.Content, anthropicBlock{
					Type: "tool_result", ToolUseID: blk.ToolUseID, Content: blk.Content, IsError: blk.IsError,
				})
			}
		}
		out = append(out, wm)
	}
	return out
}
