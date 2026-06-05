// Package server holds the HTTP server: router, auth middleware, projection-
// delta subscriptions (forthcoming), and the dependency-probe gate that runs
// before traffic is accepted. The actual lifecycle (Start / Stop / Health)
// satisfies supervisor.Component so the supervisor manages it alongside the
// bundled subprocesses.
//
// See reckon/design/05-component-architecture.md §3 for the runtime topology.
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.temporal.io/sdk/client"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/supervisor"
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

	// Handler is the aggregate command dispatcher used by /api routes. Must
	// be non-nil for any /api route to function (routes guard internally
	// with a 503 if absent so the server still serves /healthz cleanly when
	// the engine is being torn down).
	Handler *aggregate.Handler
}

// Backend is the in-process HTTP server.
type Backend struct {
	cfg BackendConfig
	sup *supervisor.Supervisor

	mu       sync.Mutex
	srv      *http.Server
	started  bool
	verifier *authz.Verifier
}

// NewBackend constructs the Backend (not yet started). The supervisor
// reference lets /status roll up every registered component including
// Backend itself.
func NewBackend(cfg BackendConfig, sup *supervisor.Supervisor) *Backend {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	return &Backend{cfg: cfg, sup: sup}
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

	mux := b.buildRouter(verifier)

	addr := fmt.Sprintf("localhost:%d", b.cfg.HTTPPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	b.mu.Lock()
	b.verifier = verifier
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

// Stop gracefully shuts the HTTP server down within ctx's deadline.
func (b *Backend) Stop(ctx context.Context) error {
	b.mu.Lock()
	srv := b.srv
	b.srv = nil
	b.started = false
	b.verifier = nil
	b.mu.Unlock()

	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
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

	// API — auth required.
	api := http.NewServeMux()

	// GET /api/me — who am I; any authenticated principal.
	api.Handle("/me", authz.RequireAuth(verifier)(http.HandlerFunc(b.handleMe)))

	// /investigations — viewer for read, analyst for write.
	api.Handle("/investigations", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.investigationsCollection),
	))
	api.Handle("/investigations/", authz.RequireAuth(verifier)(
		http.HandlerFunc(b.investigationsItem),
	))

	mux.Handle("/api/", http.StripPrefix("/api", api))

	return mux
}

// --- handlers ---------------------------------------------------------------

func (b *Backend) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintln(w, "ok")
}

// StatusResponse is the JSON shape served by /status and consumed by
// `reckon status`.
type StatusResponse struct {
	Overall    string                     `json:"overall"`
	Components map[string]ComponentStatus `json:"components"`
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
	_ = json.NewEncoder(w).Encode(MeResponse{
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
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// /investigations/{id} handles GET (load one).
func (b *Backend) investigationsItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.getInvestigation)
	default:
		w.Header().Set("Allow", "GET")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
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

// writeJSONError writes a stable error JSON shape for all non-2xx responses.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
