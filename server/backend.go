// Package server holds the HTTP server: router, auth middleware, the
// projection-delta WebSocket (handshake-authenticated, dropped on token
// expiry), and the dependency-probe gate that runs before traffic is accepted.
// The actual lifecycle (Start / Stop / Health) satisfies supervisor.Component
// so the supervisor manages it alongside the bundled subprocesses.
//
// See reckon/design/05-component-architecture.md §3 for the runtime topology.
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/supervisor"
	"github.com/sd-strax/reckon/temporal"
)

// BackendConfig configures the in-process reckon HTTP backend.
//
// Dependencies that travel as connection strings (Pg DSN, Temporal host:port,
// Keycloak issuer URL) are passed by value — the Backend depends on
// reachable services, not on the specific components that brought them up.
// This makes it cheap to repoint Backend at managed deps later (paid self-
// hosted at scale) without changing the supervisor seam.
//
// The Handler (aggregate command dispatch) is constructed by the caller
// and injected. Tests pass in a fixture-backed handler; production wires
// the real one.
type BackendConfig struct {
	// HTTPPort is the port the backend's HTTP server listens on. Default 8080.
	HTTPPort int

	// PgDSN is a libpq connection string for the aggregate's database
	// (typically the result of supervisor.Postgres.DSN("reckon_main")).
	PgDSN string

	// TemporalHostPort is host:port of the Temporal frontend gRPC.
	TemporalHostPort string

	// KeycloakIssuer is the OIDC issuer URL the realm is expected to publish.
	// At Start, Backend (1) fetches .well-known/openid-configuration and
	// asserts the issuer field matches — proves Keycloak is up AND the realm
	// exists — and (2) constructs an authz.Verifier from this URL.
	KeycloakIssuer string

	// KeycloakClientID, if set, locks the Verifier's audience check to this
	// client. Empty string disables aud-check (acceptable in OSS-solo dev;
	// production paid deployments wire the real client_id).
	KeycloakClientID string

	// KeycloakLoginClientID is the public OIDC client the interactive human
	// login flow uses (PKCE authorization-code). Advertised unauthenticated at
	// /api/auth-config so the workbench discovers the issuer + client without
	// hardcoding Keycloak's port/realm (design/13 §7 step 1). Empty leaves
	// /api/auth-config a clean 503 — the extension then reports auth
	// unconfigured rather than guessing.
	KeycloakLoginClientID string

	// Handler is the aggregate command dispatcher used by /api routes. Must
	// be non-nil for any /api route to function (routes guard internally
	// with a 503 if absent so the server still serves /healthz cleanly when
	// the engine is being torn down).
	Handler *aggregate.Handler

	// Middleware, when non-nil, wraps the entire router — it carries the
	// telemetry tracing/metrics layer (telemetry.Provider.HTTPMiddleware).
	// Injected as a function so server stays decoupled from the telemetry
	// package. Nil means no wrapping.
	Middleware func(http.Handler) http.Handler

	// MetricsHandler, when non-nil, is served at /metrics (Prometheus text
	// exposition). Nil disables the endpoint.
	MetricsHandler http.Handler

	// CapabilityResolver and CapabilityCatalog, when both non-nil, enable the
	// /api/capabilities route (the read-side capability layer, Phase B). Nil
	// leaves the route returning 503 so the backend still serves without a
	// capability config.
	CapabilityResolver *capability.Resolver
	CapabilityCatalog  *capability.Catalog

	// Gate2 and ActionCatalog, when both non-nil, enable the POST /api/actions
	// (request_action) route (the write-side authorization path, Phase C). Nil
	// leaves it a 503. The Temporal dispatch client is opened at Start
	// regardless — it also serves the export pipeline.
	Gate2         *action.Gate2
	ActionCatalog *action.ActionCatalog
	// ActionResolver, with ActionCatalog, backs GET /api/action-types — the
	// agent's write-side catalog with per-type dispatchability. Nil leaves the
	// route a clean 503.
	ActionResolver *action.ActionResolver

	// Knowledge, when non-nil, enables the SOP corpus routes (/api/sops,
	// /api/knowledge/recall_sops — Phase C.5). Nil leaves them unregistered.
	Knowledge *knowledge.Store

	// TenantNamespace is this install's identity namespace UUID (03 §7.1),
	// stamped onto export bundles + their archive path (D.5).
	TenantNamespace string

	// ExportIncludeSideStores is the tenant policy for whether export bundles
	// carry the Layer B side stores (07 §2.2). Sourced from config, NOT the
	// export requester — a compliance deployment's redaction cannot be overridden
	// per-request.
	ExportIncludeSideStores bool

	// ExportAutoOnConclude fires the post-conclusion export automatically when an
	// investigation concludes (07 §2.3). When false, export is on-demand only.
	ExportAutoOnConclude bool
}

// Backend is the in-process HTTP server.
type Backend struct {
	cfg BackendConfig
	sup *supervisor.Supervisor

	mu       sync.Mutex
	srv      *http.Server
	started  bool
	verifier *authz.Verifier

	// dispatchClient is the shared Temporal client: it starts ActionLifecycle/
	// ReversalSaga on approvals AND the PostConclusionPipeline for exports.
	// Opened at Start (Temporal is a probed dependency), independent of whether
	// the action layer is configured — the export surface must work without it.
	dispatchClient *temporal.Client

	// pipelineOverride is a test-only injection point for the export endpoint's
	// pipeline starter; nil in production (the live dispatchClient is used).
	pipelineOverride pipelineStarter

	// hub fans projection deltas out to subscribed WebSocket clients. Set at
	// construction so it outlives individual Start/Stop cycles.
	hub *hub
}

// NewBackend constructs the Backend (not yet started). The supervisor
// reference lets /status roll up every registered component including
// Backend itself.
func NewBackend(cfg BackendConfig, sup *supervisor.Supervisor) *Backend {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	return &Backend{cfg: cfg, sup: sup, hub: newHub()}
}

// Name returns "backend" — same identifier the supervisor knew it by when
// Backend lived under supervisor/. Keeps existing /status output stable.
func (b *Backend) Name() string { return "backend" }

// Start probes every dependency, constructs the authz.Verifier (which does
// OIDC discovery and so requires Keycloak to be reachable), wires the route
// table, and brings the HTTP listener up.
func (b *Backend) Start(ctx context.Context) error {
	if err := b.probePostgres(ctx); err != nil {
		return fmt.Errorf("postgres unreachable: %w", err)
	}
	if err := b.probeTemporal(ctx); err != nil {
		return fmt.Errorf("temporal unreachable: %w", err)
	}
	if err := b.probeKeycloak(ctx); err != nil {
		return fmt.Errorf("keycloak unreachable: %w", err)
	}

	verifier, err := authz.NewVerifier(ctx, authz.VerifierConfig{
		Issuer:            b.cfg.KeycloakIssuer,
		ClientID:          b.cfg.KeycloakClientID,
		SkipClientIDCheck: b.cfg.KeycloakClientID == "",
	})
	if err != nil {
		return fmt.Errorf("init verifier: %w", err)
	}

	// Open the dispatch client unconditionally (Temporal is already probed
	// reachable above). It serves the action path (ActionLifecycle on approval)
	// AND the export path (PostConclusionPipeline) — tying it to the action
	// layer would silently disable auto-export on deployments that never
	// configure write actions (07 §2.3 defaults auto-export ON).
	dispatchClient, err := temporal.NewClient(temporal.ClientConfig{HostPort: b.cfg.TemporalHostPort})
	if err != nil {
		return fmt.Errorf("start temporal dispatch client: %w", err)
	}

	mux := b.buildRouter(verifier)

	addr := fmt.Sprintf("localhost:%d", b.cfg.HTTPPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	b.mu.Lock()
	b.verifier = verifier
	b.dispatchClient = dispatchClient
	b.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	b.started = true
	srv := b.srv
	b.mu.Unlock()

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("backend http server: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts the HTTP server down within ctx's deadline. Active
// WebSocket streams are torn down explicitly via the hub — they are hijacked
// connections, which http.Server.Shutdown neither closes nor waits for.
func (b *Backend) Stop(ctx context.Context) error {
	b.mu.Lock()
	srv := b.srv
	dispatchClient := b.dispatchClient
	b.srv = nil
	b.started = false
	b.verifier = nil
	b.dispatchClient = nil
	b.mu.Unlock()

	if dispatchClient != nil {
		dispatchClient.Close()
	}
	if srv == nil {
		return nil
	}
	if b.hub != nil {
		b.hub.closeAll()
	}
	return srv.Shutdown(ctx)
}

// getDispatchClient returns the shared Temporal client under lock (nil until
// Start has run).
func (b *Backend) getDispatchClient() *temporal.Client {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dispatchClient
}

// Health reports whether the HTTP server is up. The rich "are deps healthy"
// view is at /status (which calls into the supervisor's Health rollup).
func (b *Backend) Health(_ context.Context) HealthStatus {
	b.mu.Lock()
	started := b.started
	b.mu.Unlock()
	if !started {
		return HealthStatus{Ready: false, Message: "not started"}
	}
	return HealthStatus{Ready: true, Message: fmt.Sprintf("http :%d", b.cfg.HTTPPort)}
}

// HealthStatus mirrors supervisor.HealthStatus so server can expose its own
// Health method that satisfies supervisor.Component without a forward
// dependency.
type HealthStatus = supervisor.HealthStatus

// --- routing -----------------------------------------------------------------

func (b *Backend) buildRouter(verifier *authz.Verifier) http.Handler {
	mux := http.NewServeMux()

	// Public — used by the supervisor + reckon status command.
	mux.HandleFunc("/healthz", b.handleHealthz)
	mux.HandleFunc("/status", b.handleStatus)

	// Public — Prometheus scrape endpoint. Unauthenticated in the bundled/local
	// shape (scraped over loopback); a paid/SaaS deployment fronts it with
	// network policy or an auth proxy.
	if b.cfg.MetricsHandler != nil {
		mux.Handle("/metrics", b.cfg.MetricsHandler)
	}

	// API — auth required except where noted.
	api := http.NewServeMux()

	// GET /api/auth-config — PUBLIC (must be reachable before login): the OIDC
	// issuer + public login client the workbench needs to run its PKCE flow
	// (design/13 §7). Not auth-wrapped. Clean 503 when login isn't configured.
	api.HandleFunc("/auth-config", b.handleAuthConfig)

	// GET /api/me — who am I; any authenticated principal.
	api.Handle("/me", authz.RequireAuth(verifier)(http.HandlerFunc(b.handleMe)))

	// /investigations — viewer for read, analyst for write.
	api.Handle("/investigations", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.investigationsCollection),
	))
	api.Handle("/investigations/", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.investigationsItem),
	))

	// GET /api/capabilities — list_capabilities (§2.8): the verbs resolvable in
	// this tenant and their availability. Any authenticated reader.
	api.Handle("/capabilities", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.listCapabilities),
	))

	// POST /api/capability/{verb} — verb invocation (03 §3.4, Phase E.1): the
	// agent loop's read-tool dispatch target. Analyst role.
	api.Handle("/capability/", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.capabilityInvokeRoute),
	))

	// GET /api/action-types — list_action_types (08 §3): the write-side catalog
	// (action_type, intent, tier, reversibility, D3FEND) with per-type
	// dispatchability, so the agent requests real action types instead of
	// guessing. Any authenticated reader.
	api.Handle("/action-types", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.listActionTypes),
	))

	// POST /api/actions — request_action (08 §2): propose a state-changing
	// action; runs Gate 2 and (on auto-approval) triggers dispatch. Analyst role.
	api.Handle("/actions", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.actionsCollection),
	))

	// POST /api/actions/{id}/approve|reject — the manual approval surface
	// (04 §5, Phase D): honors REQUIRE_TWO_PARTY, triggers dispatch on final
	// approval. Analyst role.
	api.Handle("/actions/", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.actionsItem),
	))

	// POST /api/interpretations — the agent loop's write into the reasoning
	// thread (05 §3.4): record one reasoning act + its transcript/tool-call side
	// store. Analyst role (the AI authors as a delegate, never a principal).
	api.Handle("/interpretations", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.interpretationsCollection),
	))

	// Knowledge service (Phase C.5): SOP corpus CRUD + keyword retrieval.
	if b.cfg.Knowledge != nil {
		api.Handle("/knowledge/recall_sops", authz.RequireAuth(verifier)(http.HandlerFunc(b.recallSOPs)))
		api.Handle("/sops", authz.RequireAuth(verifier)(http.HandlerFunc(b.sopsCollection)))
		api.Handle("/sops/", authz.RequireAuth(verifier)(http.HandlerFunc(b.sopsItem)))
	}

	// /stream — projection-delta WebSocket. Authenticated at the handshake
	// inside the handler (a WS upgrade can't go through RequireAuth, which
	// would write a non-WS error after the upgrade), not by middleware.
	if b.hub == nil {
		b.hub = newHub()
	}
	api.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		b.handleStream(w, r, verifier)
	})

	mux.Handle("/api/", http.StripPrefix("/api", api))

	if b.cfg.Middleware != nil {
		return b.cfg.Middleware(mux)
	}
	return mux
}

// --- handlers ---------------------------------------------------------------

func (b *Backend) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintln(w, "ok")
}

// APIVersion is the backend's HTTP API contract version — a single integer
// bumped only on a breaking change to the /api surface the workbench consumes
// (route removal, response-shape change, auth-flow change). It is NOT the
// product/marketing version; it is the compatibility signal the workbench pins
// against, the same philosophy as the adapter plugin protocol version
// (11 §4.1). A client that supports version N keeps working against every
// backend that serves N.
const APIVersion = 1

// StatusResponse is the JSON shape served by /status and consumed by
// `reckon status` and the workbench version handshake (design/13 §2).
type StatusResponse struct {
	Overall    string                     `json:"overall"`
	Components map[string]ComponentStatus `json:"components"`
	// APIVersion is the contract version (see APIVersion). The workbench
	// asserts it is in its supported set and fails closed with a diagnostic on
	// mismatch rather than dispatching against an incompatible surface.
	APIVersion int `json:"api_version"`
}

// ComponentStatus is the per-component slice of StatusResponse.
type ComponentStatus struct {
	Ready   bool   `json:"ready"`
	Message string `json:"message"`
}

func (b *Backend) handleStatus(w http.ResponseWriter, r *http.Request) {
	rollup := b.sup.Health(r.Context())
	resp := StatusResponse{
		Overall:    "ok",
		Components: make(map[string]ComponentStatus, len(rollup)),
		APIVersion: APIVersion,
	}
	for name, h := range rollup {
		resp.Components[name] = ComponentStatus{Ready: h.Ready, Message: h.Message}
		if !h.Ready {
			resp.Overall = "degraded"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if resp.Overall != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// AuthConfigResponse is the public shape of /api/auth-config: everything the
// workbench needs to start an OIDC PKCE login, sourced from the backend so the
// extension never hardcodes (or drifts from) Keycloak's port/realm/client.
type AuthConfigResponse struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// handleAuthConfig serves the login config unauthenticated (it is a
// prerequisite of authenticating). A 503 when login isn't configured keeps the
// contract honest: the extension reports "auth unconfigured" rather than
// guessing an issuer.
func (b *Backend) handleAuthConfig(w http.ResponseWriter, _ *http.Request) {
	if b.cfg.KeycloakLoginClientID == "" || b.cfg.KeycloakIssuer == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "interactive login not configured")
		return
	}
	writeJSON(w, http.StatusOK, AuthConfigResponse{
		Issuer:   b.cfg.KeycloakIssuer,
		ClientID: b.cfg.KeycloakLoginClientID,
	})
}

// MeResponse is the public shape of /api/me.
type MeResponse struct {
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username"`
	TenantID          string   `json:"tenant_id"`
	Roles             []string `json:"roles"`
	DelegateKind      string   `json:"delegate_kind,omitempty"`
}

func (b *Backend) handleMe(w http.ResponseWriter, r *http.Request) {
	c, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	writeJSON(w, http.StatusOK, MeResponse{
		Subject:           c.Subject,
		PreferredUsername: c.PreferredUsername,
		TenantID:          c.TenantID,
		Roles:             c.Roles,
		DelegateKind:      c.DelegateKind,
	})
}

// /investigations handles both GET (list) and POST (create) on the
// collection. Method-level role requirements differ.
func (b *Backend) investigationsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.listInvestigations)
	case http.MethodPost:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.createInvestigation)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

// /investigations/{id} handles GET (load one); the /hypotheses sub-resource
// lists the investigation's reasoning nodes (D.2); the /actions sub-resource
// lists its x-actions (the pending-approval queue + audit list); the /export
// sub-resource triggers the post-conclusion export bundle (D.5); the /lifecycle
// sub-resource drives the state machine (activate/pause/resume/conclude/reopen/
// archive, D.6).
func (b *Backend) investigationsItem(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimSuffix(r.URL.Path, "/")
	if strings.HasSuffix(trimmed, "/hypotheses") {
		switch r.Method {
		case http.MethodGet:
			b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.listInvestigationHypotheses)
		default:
			methodNotAllowed(w, "GET")
		}
		return
	}
	if strings.HasSuffix(trimmed, "/actions") {
		switch r.Method {
		case http.MethodGet:
			b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.listInvestigationActions)
		default:
			methodNotAllowed(w, "GET")
		}
		return
	}
	if strings.HasSuffix(trimmed, "/export") {
		switch r.Method {
		case http.MethodPost:
			b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.exportInvestigation)
		default:
			methodNotAllowed(w, "POST")
		}
		return
	}
	if strings.HasSuffix(trimmed, "/lifecycle") {
		switch r.Method {
		case http.MethodPost:
			b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.investigationLifecycle)
		default:
			methodNotAllowed(w, "POST")
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.getInvestigation)
	default:
		methodNotAllowed(w, "GET")
	}
}

// investigationSubresourceID parses the id out of `/investigations/{id}/<sub>`
// (the /api prefix is already stripped). The single parser for every
// investigation sub-resource route, so path handling cannot drift per-suffix.
func investigationSubresourceID(p, sub string) (uuid.UUID, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 3 || parts[0] != "investigations" || parts[2] != sub {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

// requireRolesOrDeny is an inline equivalent to authz.RequireRole, used by
// handlers that vary their role requirement per-method. Behavior matches:
// 403 with required_roles surfaced, 500 if claims context missing.
func (b *Backend) requireRolesOrDeny(w http.ResponseWriter, r *http.Request, roles []string, next http.HandlerFunc) {
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth wiring error")
		return
	}
	if !claims.HasAnyRole(roles...) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":          "required role(s) missing",
			"required_roles": roles,
			"required_any":   true,
		})
		return
	}
	next(w, r)
}

// listCapabilities serves GET /api/capabilities. Returns 503 when the capability
// layer is not configured (no tenant capability YAML); otherwise the verb
// summaries with their availability. Read requires viewer/analyst/auditor.
func (b *Backend) listCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if b.cfg.CapabilityResolver == nil || b.cfg.CapabilityCatalog == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "capability layer not configured")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, func(w http.ResponseWriter, _ *http.Request) {
		summaries := b.cfg.CapabilityResolver.ListCapabilities(b.cfg.CapabilityCatalog)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"capabilities": summaries})
	})
}

// --- dependency probes -------------------------------------------------------

func (b *Backend) probePostgres(ctx context.Context) error {
	db, err := sql.Open("postgres", b.cfg.PgDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return db.PingContext(pingCtx)
}

func (b *Backend) probeTemporal(ctx context.Context) error {
	c, err := client.Dial(client.Options{HostPort: b.cfg.TemporalHostPort})
	if err != nil {
		return err
	}
	defer c.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = c.CheckHealth(pingCtx, &client.CheckHealthRequest{})
	return err
}

func (b *Backend) probeKeycloak(ctx context.Context) error {
	url := strings.TrimRight(b.cfg.KeycloakIssuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d on %s", resp.StatusCode, url)
	}
	var disc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return fmt.Errorf("parse OIDC discovery: %w", err)
	}
	if disc.Issuer != b.cfg.KeycloakIssuer {
		return fmt.Errorf("issuer mismatch: discovery says %q, expected %q",
			disc.Issuer, b.cfg.KeycloakIssuer)
	}
	return nil
}

// writeJSON writes a JSON response with the given status. Every handler's JSON
// response goes through here (or writeJSONError) so the Content-Type is set
// uniformly — a bare Encode after WriteHeader gets content-sniffed to
// text/plain by net/http.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError writes a stable error JSON shape for all non-2xx responses.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// methodNotAllowed writes the 405 + Allow-header pair every route uses for an
// unsupported method.
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// writeCommandError maps an aggregate.Handler.Handle failure onto the HTTP
// outcome for every /api write path, so a domain rejection, a permission
// denial, a lost OCC race, and an infrastructure fault are never conflated.
// Order matters: the sentinels (which arrive wrapped in a *RejectedError) are
// matched before the generic rejection, and infrastructure failures — which
// Handle returns unwrapped — fall through to 500. The action label prefixes the
// message ("conclude", "request action", …). A nil err is a caller bug, treated
// as 500.
func writeCommandError(w http.ResponseWriter, action string, err error) {
	var rejected *aggregate.RejectedError
	switch {
	case errors.Is(err, aggregate.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, action+": investigation not found")
	case errors.Is(err, aggregate.ErrAIDenied):
		writeJSONError(w, http.StatusForbidden, action+": "+err.Error())
	case errors.Is(err, aggregate.ErrConcurrent):
		writeJSONError(w, http.StatusConflict, action+": "+err.Error())
	case errors.As(err, &rejected):
		writeJSONError(w, http.StatusUnprocessableEntity, action+": "+err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, action+": "+err.Error())
	}
}
