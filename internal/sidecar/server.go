package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/server"
)

// ProtocolVersion is the stdio protocol contract version, asserted at
// `initialize` (the extension↔sidecar half of the two handshakes,
// implementation/agent-sidecar.md §4). Bump on any breaking change to the
// method set or message shapes.
const ProtocolVersion = 1

// toolResultClip bounds the tool-result content that rides a progress
// notification. The full result went to the model and into the committed
// transcript; the notification is a render hint, not the record.
const toolResultClip = 4096

// Options assembles a Serve run.
type Options struct {
	// ServerVersion is the reckon build version, reported at initialize.
	ServerVersion string
	// NewLLM builds the model client for a session — the provider seam stays
	// with the caller (cmd/reckon injects Anthropic; tests inject a script).
	NewLLM func(model, apiKey string) agent.LLM
	// FallbackAPIKey resolves the model key when initialize carries none
	// (cmd/reckon: env → OS keychain). Optional; nil means the key must
	// arrive in initialize.
	FallbackAPIKey func() (string, error)
	// Logf writes diagnostics (stderr on the CLI — stdout is the protocol
	// channel). Optional.
	Logf func(format string, args ...any)
}

// Serve runs the sidecar protocol over r/w until the client closes the stream
// (EOF), `shutdown` is called, or ctx is canceled. The transport is
// LSP-framed JSON-RPC 2.0 — what vscode-jsonrpc speaks natively.
//
// Method surface (§4): initialize, createSession, turn, cancel, shutdown;
// notifications turn/text, turn/text_delta, turn/tool_call, turn/tool_result;
// and the getToken(kind, force) request BACK to the client — the token
// handoff (§5): the extension owns auth and refresh, this process holds
// tokens only per-call, in memory.
func Serve(ctx context.Context, r io.Reader, w io.Writer, opts Options) error {
	if opts.NewLLM == nil {
		return fmt.Errorf("sidecar: Options.NewLLM is required")
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	s := &service{opts: opts, sessions: map[string]*sessionState{}}
	s.conn = newConn(w, map[string]handler{
		"initialize":    s.handleInitialize,
		"createSession": s.handleCreateSession,
		"turn":          s.handleTurn,
		"cancel":        s.handleCancel,
		"shutdown":      func(context.Context, json.RawMessage) (any, error) { return struct{}{}, nil },
	})

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// shutdown: the response is flushed by conn before this fires; canceling
	// runCtx aborts any in-flight turn, and the client closing the pipe ends
	// runOn. Belt and braces: half-closed clients can't wedge the process.
	s.conn.onShutdown = cancel

	done := make(chan error, 1)
	go func() { done <- s.conn.runOn(runCtx, r) }()
	select {
	case err := <-done:
		return err
	case <-runCtx.Done():
		return nil
	}
}

// service is the protocol state: what initialize established, and the live
// sessions. (Not named "server" — that's the imported backend package whose
// APIVersion constant is the handshake pin.)
type service struct {
	opts Options
	conn *conn

	mu       sync.Mutex
	backend  string // backend base URL (set at initialize)
	model    string
	apiKey   string
	sessions map[string]*sessionState
}

// sessionState is one investigation's live session. turnMu serializes turns
// (agent.Session is not safe for concurrent turns); cancel aborts the
// in-flight one.
type sessionState struct {
	sess   *agent.Session
	turnMu sync.Mutex

	mu     sync.Mutex
	cancel context.CancelFunc
}

// --- initialize -------------------------------------------------------------

type initializeParams struct {
	ProtocolVersion int    `json:"protocol_version"`
	BackendURL      string `json:"backend_url"`
	Model           string `json:"model"`
	// AnthropicAPIKey is the BYOK model key from the extension's
	// SecretStorage. Optional when the sidecar host can resolve one itself
	// (env / OS keychain via Options.FallbackAPIKey).
	AnthropicAPIKey string `json:"anthropic_api_key,omitempty"`
}

type initializeResult struct {
	ProtocolVersion   int    `json:"protocol_version"`
	BackendAPIVersion int    `json:"backend_api_version"`
	ServerVersion     string `json:"server_version"`
}

// handleInitialize runs both version handshakes (§4): the stdio protocol pin
// against the client's declared version, and the backend API pin via /status —
// exactly the check the extension already performs, repeated here because the
// sidecar dispatches against that API itself. Both fail closed.
func (s *service) handleInitialize(ctx context.Context, raw json.RawMessage) (any, error) {
	var p initializeParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errInvalidParams("initialize: %v", err)
	}
	if p.ProtocolVersion != ProtocolVersion {
		return nil, &rpcErr{Code: codeInvalidParams, Message: fmt.Sprintf(
			"stdio protocol v%d unsupported (this sidecar speaks v%d) — align the extension and reckon versions",
			p.ProtocolVersion, ProtocolVersion)}
	}
	if p.BackendURL == "" {
		return nil, errInvalidParams("initialize: backend_url is required")
	}

	apiVersion, err := probeBackendAPIVersion(ctx, p.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("backend handshake at %s: %w", p.BackendURL, err)
	}
	if apiVersion != server.APIVersion {
		return nil, fmt.Errorf("backend API v%d unsupported (this sidecar speaks v%d) — align versions",
			apiVersion, server.APIVersion)
	}

	apiKey := p.AnthropicAPIKey
	if apiKey == "" && s.opts.FallbackAPIKey != nil {
		if k, kerr := s.opts.FallbackAPIKey(); kerr == nil {
			apiKey = k
		}
	}
	if apiKey == "" {
		return nil, fmt.Errorf("no Anthropic API key: pass anthropic_api_key at initialize, or configure one on this machine (`reckon set-anthropic-key` / ANTHROPIC_API_KEY)")
	}
	model := p.Model
	if model == "" {
		model = agent.DefaultAnthropicModel
	}

	s.mu.Lock()
	s.backend, s.model, s.apiKey = p.BackendURL, model, apiKey
	s.mu.Unlock()
	s.opts.Logf("initialized: backend %s (api v%d), model %s", p.BackendURL, apiVersion, model)

	return initializeResult{
		ProtocolVersion:   ProtocolVersion,
		BackendAPIVersion: apiVersion,
		ServerVersion:     s.opts.ServerVersion,
	}, nil
}

// probeBackendAPIVersion reads api_version from GET /status. A degraded
// backend answers 503 with the same body, so the status code is not gated —
// only reachability and the field's presence are.
func probeBackendAPIVersion(ctx context.Context, base string) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base+"/status", nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("backend not reachable: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		APIVersion *int `json:"api_version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode /status: %w", err)
	}
	if body.APIVersion == nil {
		return 0, fmt.Errorf("backend predates the version handshake — upgrade the backend")
	}
	return *body.APIVersion, nil
}

// --- createSession ----------------------------------------------------------

type createSessionParams struct {
	InvestigationID string `json:"investigation_id"`
}

type createSessionResult struct {
	SessionID string   `json:"session_id"`
	Tools     []string `json:"tools"`
}

// handleCreateSession assembles one agent.Session over the initialized
// backend. Its two token sources are RPC callbacks — every backend call the
// loop makes acquires a short-lived token from the extension at use time.
func (s *service) handleCreateSession(ctx context.Context, raw json.RawMessage) (any, error) {
	var p createSessionParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errInvalidParams("createSession: %v", err)
	}
	if p.InvestigationID == "" {
		return nil, errInvalidParams("createSession: investigation_id is required")
	}
	s.mu.Lock()
	backend, model, apiKey := s.backend, s.model, s.apiKey
	s.mu.Unlock()
	if backend == "" {
		return nil, fmt.Errorf("not initialized — call initialize first")
	}

	client := agent.NewClient(backend,
		&rpcTokenSource{conn: s.conn, kind: "delegate"},
		&rpcTokenSource{conn: s.conn, kind: "human"},
	)
	sessionID := uuid.NewString()
	sess, err := agent.NewSession(ctx, agent.Config{
		Backend:         client,
		LLM:             s.opts.NewLLM(model, apiKey),
		InvestigationID: p.InvestigationID,
		Hooks: agent.Hooks{
			// The two text hooks are mutually exclusive per completion (agent.Hooks
			// contract): a streaming provider delivers via turn/text_delta and
			// turn/text stays silent; a non-streaming one delivers round-complete
			// text via turn/text. The client appends both — no dedupe needed.
			OnText: func(text string) {
				s.conn.Notify("turn/text", turnTextNote{SessionID: sessionID, Text: text})
			},
			OnTextDelta: func(delta string) {
				s.conn.Notify("turn/text_delta", turnTextNote{SessionID: sessionID, Text: delta})
			},
			OnToolCall: func(name string, input json.RawMessage) {
				s.conn.Notify("turn/tool_call", turnToolCallNote{SessionID: sessionID, Name: name, Input: input})
			},
			OnToolResult: func(name, content string, isError bool) {
				note := turnToolResultNote{
					SessionID: sessionID, Name: name, Content: clipRunes(content, toolResultClip), IsError: isError,
				}
				// Summarize from the FULL payload before clipping — the client
				// renders coverage + event count + citation refs from these
				// fields, never by parsing Content (which may be clipped
				// mid-JSON). Absent when the result is not a capability
				// envelope (e.g. list_actions).
				if cov, n, refs, ok := summarizeEnvelope(content); ok && !isError {
					note.Coverage = cov
					note.EventCount = &n
					note.Refs = refs
				}
				s.conn.Notify("turn/tool_result", note)
			},
		},
	})
	if err != nil {
		return nil, err
	}

	st := &sessionState{sess: sess}
	s.mu.Lock()
	s.sessions[sessionID] = st
	s.mu.Unlock()

	var tools []string
	for _, t := range sess.Tools() {
		tools = append(tools, t.Name)
	}
	s.opts.Logf("session %s over investigation %s (%d tools)", sessionID, p.InvestigationID, len(tools))
	return createSessionResult{SessionID: sessionID, Tools: tools}, nil
}

// --- turn -------------------------------------------------------------------

type turnParams struct {
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
}

// turnResult mirrors agent.TurnResult for the wire, minus the transcript body
// (committed server-side; the extension reads reasoning state from the
// backend, not from this response). Error carries a turn that failed part-way
// — the partial result still surfaces so a proposed action is never stranded.
type turnResult struct {
	Text             string          `json:"text"`
	InterpretationID string          `json:"interpretation_id,omitempty"`
	ToolRounds       int             `json:"tool_rounds"`
	Usage            turnUsage       `json:"usage"`
	PendingActions   []pendingAction `json:"pending_actions,omitempty"`
	Error            string          `json:"error,omitempty"`
}

type turnUsage struct {
	Input      int `json:"input"`
	Output     int `json:"output"`
	CacheRead  int `json:"cache_read"`
	CacheWrite int `json:"cache_write"`
}

// pendingAction is one action awaiting the analyst, with what the approval UI
// needs to render and act (approve/reject go extension→backend directly on
// the human token — never through this process, §5).
type pendingAction struct {
	ActionID   string   `json:"action_id"`
	ActionType string   `json:"action_type"`
	Tier       string   `json:"tier"`
	Status     string   `json:"status"`
	Targets    []string `json:"targets,omitempty"`
	// Expired: the approval window elapsed — the engine refuses an approve
	// even though Status may still read pending (lazy expiry, 04). Surfaces
	// must not offer an approve affordance on these.
	Expired bool `json:"expired,omitempty"`
}

// turnTextNote rides both text notifications: turn/text carries a
// round-complete block (non-streaming provider), turn/text_delta a generated
// fragment (streaming, E.4). Renderers append either.
type turnTextNote struct {
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
}

type turnToolCallNote struct {
	SessionID string          `json:"session_id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

type turnToolResultNote struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error"`
	// Coverage + EventCount are distilled from the FULL result payload before
	// Content is clipped for transport, so the render ticker never lies about
	// a large result. Present only when the result parsed as a capability
	// envelope; EventCount is a pointer so an honest zero ("COMPLETE · 0
	// events") is distinguishable from not-an-envelope.
	Coverage   string `json:"coverage,omitempty"`
	EventCount *int   `json:"event_count,omitempty"`
	// Refs are the envelope's citation ids (observed-data, entities, raw
	// events) — what the client's pin-from-result and citation-open surfaces
	// act on (design/ui 02 §2.8), extracted pre-clip like the ticker fields.
	Refs []string `json:"refs,omitempty"`
}

// summarizeEnvelope distills a capability-envelope result into the ticker
// fields: its coverage classification, event count, and citation refs.
// ok=false when the payload is not an envelope (a plain error string, or a
// non-capability tool result like list_actions).
func summarizeEnvelope(content string) (coverage string, eventCount int, refs []string, ok bool) {
	var env struct {
		Coverage         string            `json:"coverage"`
		Events           []json.RawMessage `json:"events"`
		ObservedDataRefs []string          `json:"observed_data_refs"`
		EntityRefs       []string          `json:"entity_refs"`
		OcsfEventRefs    []string          `json:"ocsf_event_refs"`
	}
	if err := json.Unmarshal([]byte(content), &env); err != nil || env.Coverage == "" {
		return "", 0, nil, false
	}
	refs = append(refs, env.ObservedDataRefs...)
	refs = append(refs, env.EntityRefs...)
	refs = append(refs, env.OcsfEventRefs...)
	return env.Coverage, len(env.Events), refs, true
}

func (s *service) handleTurn(ctx context.Context, raw json.RawMessage) (any, error) {
	var p turnParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errInvalidParams("turn: %v", err)
	}
	st, err := s.session(p.SessionID)
	if err != nil {
		return nil, err
	}
	if !st.turnMu.TryLock() {
		return nil, fmt.Errorf("a turn is already in progress on session %s", p.SessionID)
	}
	defer st.turnMu.Unlock()

	turnCtx, cancel := context.WithCancel(ctx)
	st.mu.Lock()
	st.cancel = cancel
	st.mu.Unlock()
	defer func() {
		cancel()
		st.mu.Lock()
		st.cancel = nil
		st.mu.Unlock()
	}()

	res, turnErr := st.sess.Turn(turnCtx, p.Text)
	if res == nil {
		// No partial to surface — a hard failure before the loop produced anything.
		if turnCtx.Err() != nil {
			return nil, &rpcErr{Code: codeCancelled, Message: "turn canceled"}
		}
		return nil, turnErr
	}
	out := turnResult{
		Text:             res.Text,
		InterpretationID: res.InterpretationID,
		ToolRounds:       res.ToolRounds,
		Usage: turnUsage{
			Input: res.Usage.Input, Output: res.Usage.Output,
			CacheRead: res.Usage.CacheRead, CacheWrite: res.Usage.CacheWrite,
		},
	}
	for _, a := range res.PendingActions {
		pa := pendingAction{
			ActionID:   a.ActionID,
			ActionType: a.ActionType,
			Tier:       a.Tier,
			Status:     a.PendingLabel(),
			Expired:    a.Expired(time.Now()),
		}
		for _, t := range a.Targets {
			id := t.ResolvedIdentifier
			if id == "" {
				id = t.EntityRef
			}
			pa.Targets = append(pa.Targets, id)
		}
		out.PendingActions = append(out.PendingActions, pa)
	}
	if turnErr != nil {
		// The partial result rides the response with the error alongside —
		// mirroring Session.Turn's own contract (a failed commit still returns
		// the turn) so the surface renders what happened instead of dropping it.
		out.Error = turnErr.Error()
	}
	return out, nil
}

// --- cancel -----------------------------------------------------------------

type cancelParams struct {
	SessionID string `json:"session_id"`
}

// handleCancel aborts the session's in-flight turn, if any. Idempotent — a
// cancel that races the turn's natural end is a no-op.
func (s *service) handleCancel(_ context.Context, raw json.RawMessage) (any, error) {
	var p cancelParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errInvalidParams("cancel: %v", err)
	}
	st, err := s.session(p.SessionID)
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	if st.cancel != nil {
		st.cancel()
	}
	st.mu.Unlock()
	return struct{}{}, nil
}

func (s *service) session(id string) (*sessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[id]
	if !ok {
		return nil, errInvalidParams("unknown session %q", id)
	}
	return st, nil
}

// --- token handoff ----------------------------------------------------------

// rpcTokenSource implements agent.TokenSource by asking the CLIENT for a
// token: the getToken callback (§5). The extension owns both refresh tokens
// and the refresh cycle; this process sees only short-lived access tokens, at
// use time. Force maps to agent.TokenSource.Refresh — the 401 backstop, so
// the extension mints fresh rather than serving its cache.
type rpcTokenSource struct {
	conn *conn
	kind string // "human" | "delegate"
}

type getTokenParams struct {
	Kind  string `json:"kind"`
	Force bool   `json:"force,omitempty"`
}

type getTokenResult struct {
	Token string `json:"token"`
}

func (t *rpcTokenSource) Token(ctx context.Context) (string, error)   { return t.get(ctx, false) }
func (t *rpcTokenSource) Refresh(ctx context.Context) (string, error) { return t.get(ctx, true) }

func (t *rpcTokenSource) get(ctx context.Context, force bool) (string, error) {
	var out getTokenResult
	if err := t.conn.Call(ctx, "getToken", getTokenParams{Kind: t.kind, Force: force}, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("sidecar: client returned an empty %s token", t.kind)
	}
	return out.Token, nil
}

// clipRunes truncates s to at most n runes (rune-safe for display payloads).
func clipRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
