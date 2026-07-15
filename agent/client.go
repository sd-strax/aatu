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

// The wire types below mirror the backend's JSON contract (the seam is the
// HTTP API, exactly as the future extension consumes it — not Go types shared
// with the server package, which the v2 server-side loop must be able to
// import without a cycle). Only the fields the loop reads are mirrored.

// Capability is one /api/capabilities entry.
type Capability struct {
	Descriptor struct {
		Verb   string `json:"verb"`
		Intent string `json:"intent"`
		Inputs []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Required bool   `json:"required"`
			Desc     string `json:"desc,omitempty"`
		} `json:"inputs"`
		Output string `json:"output"`
	} `json:"descriptor"`
	Status string `json:"status"`
}

// ActionType is one /api/action-types entry — a frozen catalog descriptor plus
// its current dispatchability. The agent uses this to request real action types
// (host.isolate, ioc.block, …) instead of guessing action_type strings.
type ActionType struct {
	Descriptor struct {
		ActionType    string `json:"action_type"`
		Intent        string `json:"intent"`
		DefaultTier   string `json:"default_tier"`
		Reversibility string `json:"reversibility"`
		ReversibleBy  string `json:"reversible_by,omitempty"`
		D3FEND        string `json:"d3fend,omitempty"`
	} `json:"descriptor"`
	Status string `json:"status"` // available | degraded | unavailable
}

// InvokeInput is the body of POST /api/capability/{verb}.
type InvokeInput struct {
	Entity map[string]any `json:"entity,omitempty"`
	Window *Window        `json:"window,omitempty"`
	Extra  map[string]any `json:"extra,omitempty"`
}

// Window is a verb call's time bound.
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// InterpretationRequest is the body of POST /api/interpretations (the loop's
// write into the reasoning thread).
type InterpretationRequest struct {
	InvestigationRef   string      `json:"investigation_ref"`
	InterpretationType string      `json:"interpretation_type"`
	InputRefs          []string    `json:"input_refs,omitempty"`
	OutputRefs         []string    `json:"output_refs,omitempty"`
	Rationale          string      `json:"rationale"`
	Confidence         string      `json:"confidence,omitempty"`
	Transcript         *Transcript `json:"transcript,omitempty"`
	ToolCalls          []ToolCall  `json:"tool_calls,omitempty"`
	Hypothesis         *Hypothesis `json:"hypothesis,omitempty"`
	HypothesisRef      string      `json:"hypothesis_ref,omitempty"`
	Abandoned          bool        `json:"abandoned,omitempty"`
	Prediction         *Prediction `json:"prediction,omitempty"`
	PredictionRef      string      `json:"prediction_ref,omitempty"`
	PredictionStatus   string      `json:"prediction_status,omitempty"`
	TestResultRefs     []string    `json:"test_result_refs,omitempty"`
}

// Transcript carries a turn's raw transcript bytes for side-store hashing.
type Transcript struct {
	TurnID string `json:"turn_id,omitempty"`
	Body   string `json:"body"`
}

// ToolCall is one tool dispatch the model made during the turn.
type ToolCall struct {
	CallID   string          `json:"call_id"`
	ToolName string          `json:"tool_name"`
	Args     json.RawMessage `json:"args,omitempty"`
}

// Hypothesis is the creation payload of a new x-hypothesis.
type Hypothesis struct {
	Statement   string   `json:"statement"`
	ParentRef   string   `json:"parent_ref,omitempty"`
	RootedAtRef string   `json:"rooted_at_ref,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

// Prediction is the creation payload of a new x-prediction.
type Prediction struct {
	HypothesisRef string     `json:"hypothesis_ref"`
	Statement     string     `json:"statement"`
	TestQuery     *QuerySpec `json:"test_query,omitempty"`
}

// QuerySpec is a prediction's declared test.
type QuerySpec struct {
	Tool       string         `json:"tool"`
	QueryText  string         `json:"query_text"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// InterpretationResponse reports the appended reasoning act.
type InterpretationResponse struct {
	InterpretationID string `json:"interpretation_id"`
	SequenceNo       int64  `json:"sequence_no"`
	NodeID           string `json:"node_id,omitempty"`
}

// ActionRequest is the body of POST /api/actions (request_action, 08 §2).
type ActionRequest struct {
	ActionType       string          `json:"action_type"`
	Targets          []ActionTarget  `json:"targets"`
	Parameters       json.RawMessage `json:"parameters,omitempty"`
	EvidenceRefs     []string        `json:"evidence_refs,omitempty"`
	Rationale        string          `json:"rationale"`
	InvestigationRef string          `json:"investigation_ref"`
}

// ActionTarget names one target of an action.
type ActionTarget struct {
	EntityRef          string `json:"entity_ref"`
	ResolvedIdentifier string `json:"resolved_identifier"`
	AssetCriticality   string `json:"asset_criticality,omitempty"`
}

// ActionResponse reports the created x-action and how authorization resolved.
type ActionResponse struct {
	ActionID   string `json:"action_id"`
	Tier       string `json:"tier"`
	Status     string `json:"status"`
	Mode       string `json:"mode"`
	WorkflowID string `json:"workflow_id,omitempty"`
}

// ActionStatus is one row of GET /api/investigations/{id}/actions — the
// durable action queue, unlike ActionResponse which only reports the moment of
// request. Status is the engine's raw lifecycle status; the fallback path may
// also carry the request-time PENDING_* labels.
type ActionStatus struct {
	ActionID     string         `json:"action_id"`
	ActionType   string         `json:"action_type"`
	Tier         string         `json:"tier"`
	Status       string         `json:"status"`
	RequiredMode string         `json:"required_mode,omitempty"`
	IsReversal   bool           `json:"is_reversal,omitempty"`
	Targets      []ActionTarget `json:"targets,omitempty"`
}

// Pending reports whether the action still awaits a human approval.
func (a ActionStatus) Pending() bool {
	switch a.Status {
	case "REQUESTED", "PENDING_SECONDARY", "PENDING_MANUAL", "PENDING_TWO_PARTY":
		return true
	}
	return false
}

// PendingLabel renders the awaiting state in the request-time vocabulary
// (PENDING_MANUAL / PENDING_TWO_PARTY) surfaces already speak.
func (a ActionStatus) PendingLabel() string {
	switch {
	case a.Status == "REQUESTED" && a.RequiredMode == "TWO_PARTY":
		return "PENDING_TWO_PARTY"
	case a.Status == "REQUESTED":
		return "PENDING_MANUAL"
	case a.Status == "PENDING_SECONDARY":
		return "PENDING_TWO_PARTY"
	}
	return a.Status
}

// Investigation is the GET /api/investigations/{id} view.
type Investigation struct {
	AggregateID string `json:"aggregate_id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
}

// APIError is a non-2xx backend response, surfaced with its body so the model
// (or analyst) sees the engine's explanation — a Gate 2 denial or a guarded
// transition is information, not noise.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("backend %d: %s", e.Status, e.Body) }

// Client is the loop's HTTP client to the reckon backend. It holds two tokens
// for the same analyst: the agent token (from the reckon-agent OIDC client,
// which stamps delegate_kind issuer-side) for everything the loop does, and the
// human token (from the reckon client) for the acts that are the analyst's own
// — approvals, lifecycle transitions. The backend derives the actor from the
// token, never from the body, so using the right token per call IS the
// authorization story.
type Client struct {
	base     string
	agentSrc TokenSource
	humanSrc TokenSource
	http     *http.Client
}

// NewClient builds a backend client. base is the backend root
// (e.g. http://localhost:8080). agentSrc/humanSrc mint (and refresh) the two
// tokens; pass StaticToken(...) for a fixed token that never refreshes.
func NewClient(base string, agentSrc, humanSrc TokenSource) *Client {
	return &Client{
		base:     base,
		agentSrc: agentSrc,
		humanSrc: humanSrc,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

// do executes one JSON request against the given token source; out (when
// non-nil) receives the decoded 2xx body. A 401 — the token was rejected
// earlier than its computed expiry (clock skew, revocation) — triggers one
// forced refresh and retry, so a long-idle session recovers transparently
// instead of failing the analyst's turn. raw responses are capped defensively.
func (c *Client) do(ctx context.Context, method, path string, src TokenSource, in, out any) error {
	var reqBody []byte
	if in != nil {
		var err error
		reqBody, err = json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal %s %s: %w", method, path, err)
		}
	}

	send := func(forceRefresh bool) (*http.Response, error) {
		var (
			token string
			err   error
		)
		if forceRefresh {
			token, err = src.Refresh(ctx)
		} else {
			token, err = src.Token(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("acquire token for %s %s: %w", method, path, err)
		}
		var body io.Reader
		if reqBody != nil {
			body = bytes.NewReader(reqBody)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if reqBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return c.http.Do(req)
	}

	resp, err := send(false)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		resp, err = send(true)
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

// ListCapabilities fetches the verb catalog with availability (agent token).
func (c *Client) ListCapabilities(ctx context.Context) ([]Capability, error) {
	var out struct {
		Capabilities []Capability `json:"capabilities"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/capabilities", c.agentSrc, nil, &out); err != nil {
		return nil, err
	}
	return out.Capabilities, nil
}

// InvokeCapability executes one read verb (agent token) and returns the raw
// envelope JSON — the loop feeds it to the model as the tool result verbatim.
func (c *Client) InvokeCapability(ctx context.Context, verb string, in InvokeInput) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/api/capability/"+verb, c.agentSrc, in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListActionTypes fetches the write-side action catalog with availability
// (agent token). The loop renders it into the request_action tool so the model
// picks a real action_type. A 503 (action layer off) surfaces as an error the
// caller treats as "no catalog" — request_action stays generic.
func (c *Client) ListActionTypes(ctx context.Context) ([]ActionType, error) {
	var out struct {
		ActionTypes []ActionType `json:"action_types"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/action-types", c.agentSrc, nil, &out); err != nil {
		return nil, err
	}
	return out.ActionTypes, nil
}

// RecallSOPs runs SOP retrieval (agent token), returning the raw response.
func (c *Client) RecallSOPs(ctx context.Context, body map[string]any) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/api/knowledge/recall_sops", c.agentSrc, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordInterpretation appends one reasoning act (agent token).
func (c *Client) RecordInterpretation(ctx context.Context, body InterpretationRequest) (InterpretationResponse, error) {
	var out InterpretationResponse
	err := c.do(ctx, http.MethodPost, "/api/interpretations", c.agentSrc, body, &out)
	return out, err
}

// RequestAction proposes a state-changing action (agent token; Gate 2 and the
// baseline DENY apply server-side).
func (c *Client) RequestAction(ctx context.Context, body ActionRequest) (ActionResponse, error) {
	var out ActionResponse
	err := c.do(ctx, http.MethodPost, "/api/actions", c.agentSrc, body, &out)
	return out, err
}

// GetInvestigation loads the investigation header (agent token — a read).
func (c *Client) GetInvestigation(ctx context.Context, id string) (Investigation, error) {
	var out Investigation
	err := c.do(ctx, http.MethodGet, "/api/investigations/"+id, c.agentSrc, nil, &out)
	return out, err
}

// ListHypotheses returns the investigation's reasoning nodes as raw JSON for
// prompt context.
func (c *Client) ListHypotheses(ctx context.Context, id string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.do(ctx, http.MethodGet, "/api/investigations/"+id+"/hypotheses", c.agentSrc, nil, &out)
	return out, err
}

// ListActions returns the investigation's x-actions with their current status
// (agent token — a read). The durable source of the pending-approval queue.
func (c *Client) ListActions(ctx context.Context, id string) ([]ActionStatus, error) {
	var out struct {
		Actions []ActionStatus `json:"actions"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/investigations/"+id+"/actions", c.agentSrc, nil, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// ApproveAction approves a pending action AS THE HUMAN (human token): approval
// is the analyst's act, never the delegate's — the backend rejects an agent
// token here regardless.
func (c *Client) ApproveAction(ctx context.Context, actionID, challengeResponse string) (json.RawMessage, error) {
	body := map[string]any{}
	if challengeResponse != "" {
		body["challenge_response"] = challengeResponse
	}
	var out json.RawMessage
	err := c.do(ctx, http.MethodPost, "/api/actions/"+actionID+"/approve", c.humanSrc, body, &out)
	return out, err
}

// RejectAction rejects a pending action as the human.
func (c *Client) RejectAction(ctx context.Context, actionID, reason string) (json.RawMessage, error) {
	body := map[string]any{"reason": reason}
	var out json.RawMessage
	err := c.do(ctx, http.MethodPost, "/api/actions/"+actionID+"/reject", c.humanSrc, body, &out)
	return out, err
}
