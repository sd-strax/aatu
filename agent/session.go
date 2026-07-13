package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// maxRationaleRunes mirrors the aggregate's rationale bound (01: "terse by
// design"). The loop clips before sending; full detail lives in the transcript.
const maxRationaleRunes = 500

// defaultMaxToolRounds bounds the model↔tool loop within one analyst turn. A
// full pivot rarely needs more than a handful; the bound stops a looping model
// from burning the tool budget unattended.
const defaultMaxToolRounds = 16

// defaultMaxTokens is the per-completion output budget.
const defaultMaxTokens = 4096

// Hooks lets the surface render progress as the turn executes. All fields are
// optional.
type Hooks struct {
	OnText       func(text string)                        // model text as each round completes
	OnToolCall   func(name string, input json.RawMessage) // a tool is about to dispatch
	OnToolResult func(name string, content string, isError bool)
}

// Config assembles a session.
type Config struct {
	Backend         *Client
	LLM             LLM
	InvestigationID string
	MaxToolRounds   int
	MaxTokens       int
	Hooks           Hooks
}

// Session is one analyst's interactive loop over one investigation. Not safe
// for concurrent turns — the conversation is ordered.
type Session struct {
	backend         *Client
	llm             LLM
	investigationID string
	maxRounds       int
	maxTokens       int
	hooks           Hooks

	system   string
	tools    []ToolDef
	messages []Message

	pendingActions []ActionResponse // actions proposed this turn, for the surface to offer approval
}

// TurnResult is what one analyst turn produced.
type TurnResult struct {
	// Text is the model's final response text.
	Text string
	// InterpretationID is the committed turn-summary reasoning act.
	InterpretationID string
	// PendingActions are actions the model proposed this turn that await the
	// analyst (PENDING_MANUAL / PENDING_TWO_PARTY) — the surface offers approval.
	PendingActions []ActionResponse
	// ToolRounds is how many model→tool rounds the turn took.
	ToolRounds int
}

// NewSession assembles the session: investigation context and the live tool
// set are fetched once (05 §3.4 steps 2–4); the system prompt embeds both.
func NewSession(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Backend == nil || cfg.LLM == nil {
		return nil, fmt.Errorf("agent: Backend and LLM are required")
	}
	s := &Session{
		backend:         cfg.Backend,
		llm:             cfg.LLM,
		investigationID: cfg.InvestigationID,
		maxRounds:       cfg.MaxToolRounds,
		maxTokens:       cfg.MaxTokens,
		hooks:           cfg.Hooks,
	}
	if s.maxRounds <= 0 {
		s.maxRounds = defaultMaxToolRounds
	}
	if s.maxTokens <= 0 {
		s.maxTokens = defaultMaxTokens
	}

	inv, err := s.backend.GetInvestigation(ctx, s.investigationID)
	if err != nil {
		return nil, fmt.Errorf("agent: load investigation: %w", err)
	}
	caps, err := s.backend.ListCapabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent: list capabilities: %w", err)
	}
	// Hypotheses are optional context — a fresh investigation has none.
	hyps, err := s.backend.ListHypotheses(ctx, s.investigationID)
	if err != nil {
		hyps = nil
	}

	s.tools = buildTools(caps)
	s.system = systemPrompt(inv, caps, hyps)
	return s, nil
}

// Tools exposes the assembled tool set (for surfaces that display it).
func (s *Session) Tools() []ToolDef { return s.tools }

// Turn runs one analyst turn: the model reasons and dispatches tools until it
// ends its turn (or the round budget is spent), then the whole turn — full
// transcript bytes plus the tool-call log — is committed to the reasoning
// thread as one interpretation (05 §3.4). The turn is returned even when the
// final commit fails; the error reports the commit failure.
func (s *Session) Turn(ctx context.Context, userMsg string) (*TurnResult, error) {
	s.pendingActions = nil
	turnID := uuid.NewString()

	var transcript strings.Builder
	fmt.Fprintf(&transcript, "[user] %s\n", userMsg)

	var toolLog []ToolCall
	var finalText strings.Builder
	s.messages = append(s.messages, Message{Role: RoleUser, Content: []ContentBlock{TextBlock(userMsg)}})

	rounds := 0
	for {
		resp, err := s.llm.Complete(ctx, CompleteRequest{
			System:    s.system,
			Messages:  s.messages,
			Tools:     s.tools,
			MaxTokens: s.maxTokens,
		})
		if err != nil {
			return nil, fmt.Errorf("agent: model call: %w", err)
		}
		s.messages = append(s.messages, Message{Role: RoleAssistant, Content: resp.Content})

		var toolUses []ContentBlock
		for _, blk := range resp.Content {
			switch blk.Type {
			case BlockText:
				if blk.Text != "" {
					fmt.Fprintf(&transcript, "[assistant] %s\n", blk.Text)
					finalText.WriteString(blk.Text)
					if s.hooks.OnText != nil {
						s.hooks.OnText(blk.Text)
					}
				}
			case BlockToolUse:
				toolUses = append(toolUses, blk)
			}
		}

		if resp.StopReason != StopToolUse || len(toolUses) == 0 {
			break
		}
		rounds++
		if rounds > s.maxRounds {
			fmt.Fprintf(&transcript, "[loop] tool budget exhausted after %d rounds\n", s.maxRounds)
			break
		}

		var results []ContentBlock
		for _, tu := range toolUses {
			fmt.Fprintf(&transcript, "[tool_use %s id=%s] %s\n", tu.ToolName, tu.ToolUseID, string(tu.Input))
			toolLog = append(toolLog, ToolCall{CallID: tu.ToolUseID, ToolName: tu.ToolName, Args: tu.Input})
			if s.hooks.OnToolCall != nil {
				s.hooks.OnToolCall(tu.ToolName, tu.Input)
			}

			content, isErr := s.dispatchTool(ctx, tu.ToolName, tu.Input)
			fmt.Fprintf(&transcript, "[tool_result %s id=%s error=%v] %s\n", tu.ToolName, tu.ToolUseID, isErr, content)
			if s.hooks.OnToolResult != nil {
				s.hooks.OnToolResult(tu.ToolName, content, isErr)
			}
			results = append(results, ContentBlock{
				Type:      BlockToolResult,
				ToolUseID: tu.ToolUseID,
				Content:   content,
				IsError:   isErr,
			})
		}
		s.messages = append(s.messages, Message{Role: RoleUser, Content: results})
	}

	res := &TurnResult{
		Text:           finalText.String(),
		PendingActions: s.pendingActions,
		ToolRounds:     rounds,
	}

	// Commit the turn to the reasoning thread: the transcript bytes are hashed
	// into the content-addressed side store and the tool-call log rides the same
	// transaction (05 §3.4). The rationale is the terse summary; the transcript
	// is the record.
	rationale := clipRunes(strings.TrimSpace(finalText.String()), maxRationaleRunes)
	if rationale == "" {
		rationale = "(no final text — see transcript)"
	}
	interp, err := s.backend.RecordInterpretation(ctx, InterpretationRequest{
		InvestigationRef:   s.investigationID,
		InterpretationType: "other",
		Rationale:          rationale,
		Transcript:         &Transcript{TurnID: turnID, Body: transcript.String()},
		ToolCalls:          toolLog,
	})
	if err != nil {
		return res, fmt.Errorf("agent: commit turn: %w", err)
	}
	res.InterpretationID = interp.InterpretationID
	return res, nil
}

// clipRunes truncates s to at most n runes.
func clipRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
