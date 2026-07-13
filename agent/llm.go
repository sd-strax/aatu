// Package agent is the interactive investigation loop (05 §3.4, Phase E): it
// assembles LLM tool definitions from the backend's capability catalog plus the
// intrinsic reasoning/action tools, drives the model↔tool conversation for one
// analyst turn at a time, and commits each turn to the reasoning thread with its
// full transcript and tool-call log.
//
// The loop runs CLIENT-side by architectural commitment (05 §2.7): the LLM
// credential lives with the surface (CLI today, VS Code extension later) and
// never crosses to the backend. Every backend call the loop makes carries the
// AI-delegate token, so the engine's write protections (aggregate allowlist,
// Gate 2 baseline DENY) hold regardless of what the model asks for.
package agent

import (
	"context"
	"encoding/json"
)

// Role is a conversation message's author.
type Role string

// Conversation roles. The system prompt travels separately (CompleteRequest
// .System), matching provider APIs.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Content block types.
const (
	BlockText       = "text"
	BlockToolUse    = "tool_use"
	BlockToolResult = "tool_result"
)

// ContentBlock is one part of a message: model text, a model-issued tool call,
// or a tool result fed back by the loop.
type ContentBlock struct {
	Type string

	// BlockText
	Text string

	// BlockToolUse
	ToolUseID string
	ToolName  string
	Input     json.RawMessage

	// BlockToolResult (ToolUseID identifies the call it answers)
	Content string
	IsError bool
}

// Message is one conversation entry.
type Message struct {
	Role    Role
	Content []ContentBlock
}

// TextBlock builds a plain text block.
func TextBlock(s string) ContentBlock { return ContentBlock{Type: BlockText, Text: s} }

// ToolDef is one tool advertised to the model. InputSchema is a JSON Schema
// object (the provider adapters pass it through verbatim).
type ToolDef struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// Stop reasons.
const (
	StopEndTurn   = "end_turn"
	StopToolUse   = "tool_use"
	StopMaxTokens = "max_tokens"
)

// CompleteRequest is one model call: the system prompt, the conversation so
// far, and the tool definitions.
type CompleteRequest struct {
	System    string
	Messages  []Message
	Tools     []ToolDef
	MaxTokens int
}

// CompleteResponse is the model's reply: content blocks (text and/or tool_use)
// and the stop reason.
type CompleteResponse struct {
	Content    []ContentBlock
	StopReason string
}

// LLM is the provider seam. The Anthropic implementation lands with the CLI
// surface (E.3); tests drive the loop with a scripted fake.
type LLM interface {
	Complete(ctx context.Context, req CompleteRequest) (CompleteResponse, error)
}
