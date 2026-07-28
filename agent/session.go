package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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

	// OnTextDelta receives text fragments as the model generates them (E.4).
	// When set and the LLM implements StreamingLLM, completions stream and a
	// streamed completion's text arrives ONLY here — OnText is not called for
	// it (the deltas were the delivery; a surface that got both would render
	// the text twice). OnText still fires when the LLM cannot stream, so a
	// surface sets both and renders whichever arrives.
	OnTextDelta func(delta string)

	// OnRoundStart fires as each model↔tool round begins (1-based) — the
	// step marker surfaces group tool calls under (design/ui binding §2.6).
	OnRoundStart func(round int)
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
	// consulted accumulates the turn's recall_sops retrievals (by sop_id,
	// keeping the best score) — the knowledge provenance the commit carries.
	consulted map[string]ConsultedSOP
}

// TurnResult is what one analyst turn produced.
type TurnResult struct {
	// Text is the model's final response text.
	Text string
	// InterpretationID is the committed turn-summary reasoning act.
	InterpretationID string
	// PendingActions are ALL of the investigation's actions still awaiting the
	// analyst (not just this turn's proposals) — refreshed from the backend at
	// turn end, so an approval missed on an earlier turn is re-offered rather
	// than stranded. The surface offers approval on each.
	PendingActions []ActionStatus
	// ToolRounds is how many model→tool rounds the turn took.
	ToolRounds int
	// Transcript is the turn's committed transcript — the exact bytes that were
	// content-hashed into the side store (10 §1.1): Turn fails when the commit
	// fails, so a returned Transcript with a non-empty InterpretationID IS the
	// persisted record, byte for byte. The eval harness grades this (10 §5)
	// instead of scraping hook output.
	Transcript string
	// ToolCalls is the turn's committed tool-call log — the same slice that rode
	// the commit transaction (05 §3.4).
	ToolCalls []ToolCall
	// Usage is the token accounting summed over every model call this turn made
	// (a turn spans one call per tool round). Surfaces feed it to a cost readout;
	// the eval harness aggregates it into the run report.
	Usage Usage
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
	// The write-side action catalog shapes request_action so the model uses real
	// action types. Optional: a 503 (action layer off) leaves request_action
	// generic, exactly as before.
	actionTypes, err := s.backend.ListActionTypes(ctx)
	if err != nil {
		actionTypes = nil
	}

	s.tools = buildTools(caps, actionTypes)
	s.system = systemPrompt(inv, caps, hyps)
	return s, nil
}

// Tools exposes the assembled tool set (for surfaces that display it).
func (s *Session) Tools() []ToolDef { return s.tools }

// System exposes the assembled system prompt. The eval harness hashes it as the
// prompt-version identifier for run attribution (09 §4.2, 10 §1.4) until the
// product stamps a version itself.
func (s *Session) System() string { return s.system }

// Turn runs one analyst turn: the model reasons and dispatches tools until it
// ends its turn (or the round budget is spent), then the whole turn — full
// transcript bytes plus the tool-call log — is committed to the reasoning
// thread as one interpretation (05 §3.4). The turn is returned even when the
// final commit fails; the error reports the commit failure.
func (s *Session) Turn(ctx context.Context, userMsg string) (*TurnResult, error) {
	s.pendingActions = nil
	s.consulted = map[string]ConsultedSOP{}
	turnID := uuid.NewString()

	var transcript strings.Builder
	fmt.Fprintf(&transcript, "[user] %s\n", sanitizeTranscript(userMsg))

	var toolLog []ToolCall
	var turnUsage Usage
	var finalText strings.Builder
	// A turn aborted by a model-call failure leaves the history ending in a
	// user message (the tool results, or the aborted turn's own text). Merge
	// rather than append a sibling — consecutive same-role messages violate the
	// provider contract.
	if n := len(s.messages); n > 0 && s.messages[n-1].Role == RoleUser {
		s.messages[n-1].Content = append(s.messages[n-1].Content, TextBlock(userMsg))
	} else {
		s.messages = append(s.messages, Message{Role: RoleUser, Content: []ContentBlock{TextBlock(userMsg)}})
	}

	rounds := 0
	for {
		if s.hooks.OnRoundStart != nil {
			s.hooks.OnRoundStart(rounds + 1)
		}
		resp, streamed, err := s.complete(ctx)
		if err != nil {
			// Return a partial result rather than nil: any action the model
			// already requested this turn is recorded server-side and pending —
			// dropping the result would strand it past the surface's approval
			// offer (the exact failure mode the durable queue exists to fix).
			return &TurnResult{
				Text:           finalText.String(),
				PendingActions: s.refreshPending(ctx),
				ToolRounds:     rounds,
				Transcript:     transcript.String(),
				ToolCalls:      toolLog,
				Usage:          turnUsage,
			}, fmt.Errorf("agent: model call: %w", err)
		}
		turnUsage.Add(resp.Usage)
		s.messages = append(s.messages, Message{Role: RoleAssistant, Content: resp.Content})

		var toolUses []ContentBlock
		for _, blk := range resp.Content {
			switch blk.Type {
			case BlockText:
				if blk.Text != "" {
					fmt.Fprintf(&transcript, "[assistant] %s\n", sanitizeTranscript(blk.Text))
					finalText.WriteString(blk.Text)
					// A streamed completion's text already reached the surface as
					// deltas (Hooks contract) — firing OnText too would double it.
					if !streamed && s.hooks.OnText != nil {
						s.hooks.OnText(blk.Text)
					}
				}
			case BlockToolUse:
				toolUses = append(toolUses, blk)
			}
		}

		if resp.StopReason != StopToolUse || len(toolUses) == 0 {
			// A stop that still carried tool calls (a max_tokens cut-off
			// mid-tool_use) must not leave them dangling: every tool_use has to be
			// answered by a tool_result, or the NEXT turn's model call — this
			// session's message history is reused across turns — is a contract
			// violation the provider rejects. Close them off.
			s.abandonToolUses(&transcript, toolUses, "turn ended before this tool was dispatched")
			break
		}
		rounds++
		if rounds > s.maxRounds {
			fmt.Fprintf(&transcript, "[loop] tool budget exhausted after %d rounds\n", s.maxRounds)
			s.abandonToolUses(&transcript, toolUses, "tool budget exhausted; tool not dispatched")
			break
		}

		var results []ContentBlock
		for _, tu := range toolUses {
			fmt.Fprintf(&transcript, "[tool_use %s id=%s] %s\n",
				sanitizeTranscript(tu.ToolName), sanitizeTranscript(tu.ToolUseID), sanitizeTranscript(string(tu.Input)))
			toolLog = append(toolLog, ToolCall{CallID: tu.ToolUseID, ToolName: tu.ToolName, Args: tu.Input})
			if s.hooks.OnToolCall != nil {
				s.hooks.OnToolCall(tu.ToolName, tu.Input)
			}

			content, isErr := s.dispatchTool(ctx, tu.ToolName, tu.Input)
			if tu.ToolName == ToolRecallSOPs && !isErr {
				s.trackConsulted(content)
			}
			fmt.Fprintf(&transcript, "[tool_result %s id=%s error=%v] %s\n",
				sanitizeTranscript(tu.ToolName), sanitizeTranscript(tu.ToolUseID), isErr, sanitizeTranscript(content))
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
		PendingActions: s.refreshPending(ctx),
		ToolRounds:     rounds,
		Transcript:     transcript.String(),
		ToolCalls:      toolLog,
		Usage:          turnUsage,
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
		ConsultedSOPs:      s.consultedList(finalText.String()),
	})
	if err != nil {
		return res, fmt.Errorf("agent: commit turn: %w", err)
	}
	res.InterpretationID = interp.InterpretationID
	return res, nil
}

// complete runs one model call, streaming when both sides can (the surface
// registered OnTextDelta and the provider implements StreamingLLM). streamed
// reports whether deltas carried the text, so the caller skips OnText for it.
func (s *Session) complete(ctx context.Context) (resp CompleteResponse, streamed bool, err error) {
	req := CompleteRequest{
		System:    s.system,
		Messages:  s.messages,
		Tools:     s.tools,
		MaxTokens: s.maxTokens,
	}
	if s.hooks.OnTextDelta != nil {
		if sl, ok := s.llm.(StreamingLLM); ok {
			resp, err = sl.CompleteStream(ctx, req, s.hooks.OnTextDelta)
			return resp, true, err
		}
	}
	resp, err = s.llm.Complete(ctx, req)
	return resp, false, err
}

// trackConsulted accumulates one recall_sops result's retrievals into the
// turn's knowledge provenance (dedup by sop_id, best score kept).
func (s *Session) trackConsulted(content string) {
	var res struct {
		Results []struct {
			SOPID string  `json:"sop_id"`
			Title string  `json:"title"`
			Score float64 `json:"score"`
		} `json:"results"`
	}
	if json.Unmarshal([]byte(content), &res) != nil {
		return
	}
	for _, r := range res.Results {
		if r.SOPID == "" {
			continue
		}
		if prev, ok := s.consulted[r.SOPID]; !ok || r.Score > prev.RetrievalScore {
			s.consulted[r.SOPID] = ConsultedSOP{SOPID: r.SOPID, Title: r.Title, RetrievalScore: r.Score}
		}
	}
}

// consultedList finalizes the turn's knowledge provenance. Used is decided
// CONSERVATIVELY: only when the model's own final text references the SOP (by
// title or id) — retrieval alone is "consulted, not applied", and overclaiming
// "followed the SOP" would be fabricated provenance (01 schema; the transcript
// is deliberately not searched: it contains the retrieval results themselves,
// which would mark everything used).
func (s *Session) consultedList(finalText string) []ConsultedSOP {
	if len(s.consulted) == 0 {
		return nil
	}
	lower := strings.ToLower(finalText)
	out := make([]ConsultedSOP, 0, len(s.consulted))
	for _, c := range s.consulted {
		c.Used = (c.Title != "" && strings.Contains(lower, strings.ToLower(c.Title))) ||
			strings.Contains(lower, strings.ToLower(c.SOPID))
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RetrievalScore > out[j].RetrievalScore })
	return out
}

// refreshPending returns the investigation's actions still awaiting approval,
// straight from the backend — the authoritative queue, covering actions from
// earlier turns (or earlier sessions) whose approval offer was missed. When the
// list endpoint fails, it degrades to this turn's request responses so a
// just-proposed action is still offered.
func (s *Session) refreshPending(ctx context.Context) []ActionStatus {
	if acts, err := s.backend.ListActions(ctx, s.investigationID); err == nil {
		var out []ActionStatus
		for _, a := range acts {
			if a.Pending() {
				out = append(out, a)
			}
		}
		return out
	}
	var out []ActionStatus
	for _, r := range s.pendingActions {
		if r.Status == "PENDING_MANUAL" || r.Status == "PENDING_TWO_PARTY" {
			out = append(out, ActionStatus{ActionID: r.ActionID, Tier: r.Tier, Status: r.Status})
		}
	}
	return out
}

// abandonToolUses closes off tool calls the turn accepted but is breaking away
// from without dispatching (the round budget is spent, or the model stopped
// mid-tool_use on max_tokens). The Messages API requires every tool_use to be
// answered by a tool_result; because the session reuses its message history
// across turns, a dangling tool_use would make every subsequent turn's model
// call fail. Synthetic is_error results keep the conversation valid and tell the
// model why the call did not run.
func (s *Session) abandonToolUses(transcript *strings.Builder, toolUses []ContentBlock, reason string) {
	if len(toolUses) == 0 {
		return
	}
	results := make([]ContentBlock, 0, len(toolUses))
	for _, tu := range toolUses {
		fmt.Fprintf(transcript, "[tool_result %s id=%s error=true] %s\n",
			sanitizeTranscript(tu.ToolName), sanitizeTranscript(tu.ToolUseID), reason)
		results = append(results, ContentBlock{
			Type:      BlockToolResult,
			ToolUseID: tu.ToolUseID,
			Content:   reason,
			IsError:   true,
		})
	}
	s.messages = append(s.messages, Message{Role: RoleUser, Content: results})
}

// sanitizeTranscript neutralizes line breaks in model- or tool-supplied text
// before it is interpolated into the line-framed transcript. The transcript is
// the content-hashed audit record; without this, model output (or an injected
// tool result) could embed a literal newline followed by a fake "[tool_result
// ...]" / "[tool_use ...]" line and masquerade as reckon's own framing. The
// structured tool-call log is built from the real dispatch, not this text, so it
// is unaffected either way — this closes the human-readable-record gap.
func sanitizeTranscript(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\n", "\\n", "\r", "\\r").Replace(s)
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
