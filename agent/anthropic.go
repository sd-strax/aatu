package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// DefaultAnthropicModel is the v0 default for the interactive loop. Overridable
// per session — the loop treats model choice as configuration, not code.
const DefaultAnthropicModel = "claude-sonnet-4-6"

const (
	anthropicBaseURL = "https://api.anthropic.com"
	anthropicVersion = "2023-06-01"
)

const (
	// Transient-error retry budget for the Messages API. A 429/5xx/529 is
	// provider-side backpressure (rate limit, transient fault, "overloaded"),
	// not a request defect — riding it out with exponential backoff keeps a long
	// agent turn, or an unattended eval trial, from dying on a momentary blip
	// (the 529 overloaded_error is the common one). defaultAnthropicRetries
	// retries → up to that many + 1 attempts.
	defaultAnthropicRetries = 4
	anthropicRetryBase      = 2 * time.Second
	anthropicRetryMax       = 30 * time.Second
)

// Anthropic implements LLM over the Anthropic Messages API with the analyst's
// own key (BYOK, 05 §2.7): the key lives in this client-side process and is
// sent only to the provider — never to the reckon backend.
type Anthropic struct {
	APIKey  string
	Model   string       // defaults to DefaultAnthropicModel
	BaseURL string       // defaults to the public API; overridable for tests
	HTTP    *http.Client // defaults to a 300s-timeout client (long completions)

	// MaxRetries bounds transient-error retries (429/5xx/529). Zero uses
	// defaultAnthropicRetries; a negative value disables retries.
	MaxRetries int
	// RetryBaseDelay is the first backoff step (doubled per attempt, capped).
	// Zero uses anthropicRetryBase; overridable to keep tests fast.
	RetryBaseDelay time.Duration
	// OnRetry, when set, is called before each backoff sleep so a surface can
	// report the wait (a silent 30s pause otherwise looks like a hang). attempt
	// is 1-based (the attempt that just failed); err is why.
	OnRetry func(attempt int, wait time.Duration, err error)
	// DisableCaching turns off prompt-cache breakpoints. Default (false) caches
	// the repeated system+tools prefix and the accumulating conversation, which
	// is purely beneficial for the loop; set true only against a gateway that
	// rejects cache_control.
	DisableCaching bool
}

// Messages API wire shapes (only the fields the loop uses).

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    []anthropicText    `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
}

// anthropicText is a system-prompt block (the array form of `system`, which the
// string form does not allow a cache_control breakpoint on).
type anthropicText struct {
	Type         string        `json:"type"` // "text"
	Text         string        `json:"text"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

// cacheControl marks a prompt-caching breakpoint: everything in the request up
// to and including the marked element is cached and, on a later call within the
// TTL, billed as a cheap cache read instead of full input (05 §2.7).
type cacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

func ephemeral() *cacheControl { return &cacheControl{Type: "ephemeral"} }

type anthropicTool struct {
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	InputSchema  map[string]any `json:"input_schema"`
	CacheControl *cacheControl  `json:"cache_control,omitempty"`
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

	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type anthropicResponse struct {
	Content    []anthropicBlock `json:"content"`
	StopReason string           `json:"stop_reason"`
	Usage      anthropicUsage   `json:"usage"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// anthropicUsage is the per-call token accounting. input_tokens excludes the
// cache counters, which Anthropic reports separately.
type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
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
		Messages:  toAnthropicMessages(req.Messages),
	}
	if req.System != "" {
		wire.System = []anthropicText{{Type: "text", Text: req.System}}
	}
	for _, t := range req.Tools {
		wire.Tools = append(wire.Tools, anthropicTool{
			Name: t.Name, Description: t.Description, InputSchema: t.InputSchema,
		})
	}
	// Prompt caching (05 §2.7): the agentic loop resends the same system prompt
	// and tool set on every call (~15 per trial), and a growing conversation
	// prefix within a turn's tool rounds. Marking those static/accumulating
	// prefixes with cache breakpoints bills them as cheap cache reads after the
	// first call instead of full input every time — the dominant cost. Cheaper
	// than sending them uncached and harmless below the cache minimum (the
	// marker is ignored). Disable with DisableCaching (e.g. an unsupported base).
	if !a.DisableCaching {
		markCacheBreakpoints(&wire)
	}

	raw, err := json.Marshal(wire)
	if err != nil {
		return CompleteResponse{}, fmt.Errorf("anthropic: marshal: %w", err)
	}

	retries := a.MaxRetries
	if retries == 0 {
		retries = defaultAnthropicRetries
	}
	retryBase := a.RetryBaseDelay
	if retryBase <= 0 {
		retryBase = anthropicRetryBase
	}

	// attempt is 1-based: attempt 1 is the first try, then up to `retries` more.
	for attempt := 1; ; attempt++ {
		res, retryable, retryAfter, err := a.doOnce(ctx, base, httpc, raw)
		if err == nil {
			return res, nil
		}
		if !retryable || attempt > retries {
			return CompleteResponse{}, err
		}
		wait := backoffDelay(retryBase, attempt, retryAfter)
		if a.OnRetry != nil {
			a.OnRetry(attempt, wait, err)
		}
		select {
		case <-ctx.Done():
			return CompleteResponse{}, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// doOnce runs one Messages call. It reports whether a failure is worth retrying
// (transport blip, 429/5xx/529) and any provider-supplied Retry-After, so
// Complete can back off; a request defect (4xx other than 429) is terminal.
func (a *Anthropic) doOnce(ctx context.Context, base string, httpc *http.Client, raw []byte) (CompleteResponse, bool, time.Duration, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(raw))
	if err != nil {
		return CompleteResponse{}, false, 0, err
	}
	httpReq.Header.Set("x-api-key", a.APIKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := httpc.Do(httpReq)
	if err != nil {
		// Transport-level failure (connection reset, timeout): transient, retry.
		return CompleteResponse{}, true, 0, fmt.Errorf("anthropic: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return CompleteResponse{}, true, 0, fmt.Errorf("anthropic: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var out anthropicResponse
		_ = json.Unmarshal(body, &out)
		msg := string(body)
		if out.Error != nil {
			msg = out.Error.Type + ": " + out.Error.Message
		}
		return CompleteResponse{}, isRetryableStatus(resp.StatusCode), retryAfter(resp.Header),
			fmt.Errorf("anthropic: %d %s", resp.StatusCode, msg)
	}

	var out anthropicResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return CompleteResponse{}, false, 0, fmt.Errorf("anthropic: decode (%d): %w", resp.StatusCode, err)
	}
	res := CompleteResponse{
		StopReason: out.StopReason,
		Usage: Usage{
			Input:      out.Usage.InputTokens,
			Output:     out.Usage.OutputTokens,
			CacheWrite: out.Usage.CacheCreationInputTokens,
			CacheRead:  out.Usage.CacheReadInputTokens,
		},
	}
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
	return res, false, 0, nil
}

// markCacheBreakpoints places prompt-cache breakpoints on the request's stable
// and accumulating prefixes (05 §2.7): the last system block and the last tool
// (the static system+tools prefix, resent every call) and the last content
// block of the last message (so a turn's growing tool-round history is cached
// incrementally). At most three of the four allowed breakpoints; each is a
// no-op below the model's cache minimum.
func markCacheBreakpoints(wire *anthropicRequest) {
	if n := len(wire.System); n > 0 {
		wire.System[n-1].CacheControl = ephemeral()
	}
	if n := len(wire.Tools); n > 0 {
		wire.Tools[n-1].CacheControl = ephemeral()
	}
	if n := len(wire.Messages); n > 0 {
		if c := len(wire.Messages[n-1].Content); c > 0 {
			wire.Messages[n-1].Content[c-1].CacheControl = ephemeral()
		}
	}
}

// isRetryableStatus reports whether an HTTP status is provider-side backpressure
// worth retrying: 429 (rate limit), 500/502/503 (transient fault), and 529
// (Anthropic's non-standard overloaded_error). Every other 4xx is a request
// defect that a retry would only repeat.
func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		529:                            // overloaded_error (no net/http constant)
		return true
	}
	return false
}

// retryAfter parses a Retry-After header expressed in seconds (the form the
// Messages API sends on 429); an absent or non-integer value yields 0, leaving
// Complete to fall back to exponential backoff.
func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// backoffDelay is the wait before a retry: a provider-supplied Retry-After when
// present (capped), else exponential backoff (base·2^(attempt-1)) with full
// jitter over the lower half, capped at anthropicRetryMax. Jitter is derived
// from the wall clock — good enough to desynchronize retries without a PRNG
// dependency.
func backoffDelay(base time.Duration, attempt int, ra time.Duration) time.Duration {
	if ra > 0 {
		return capDelay(ra)
	}
	shift := attempt - 1
	if shift > 16 { // guard the shift; the cap dominates well before this
		shift = 16
	}
	d := capDelay(base << shift)
	half := d / 2
	jitter := time.Duration(time.Now().UnixNano() % int64(half+1))
	return half + jitter
}

func capDelay(d time.Duration) time.Duration {
	if d > anthropicRetryMax {
		return anthropicRetryMax
	}
	return d
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
