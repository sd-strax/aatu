package supervisor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"go.temporal.io/sdk/client"
)

// BackendConfig configures the in-process aatu backend.
//
// Dependencies are passed as connection strings rather than component
// references — the Backend depends on Pg + Temporal + Keycloak being
// reachable, not on the specific components that brought them up. This makes
// it cheap to point Backend at managed deps later (paid self-hosted at scale)
// without changing the supervisor seam.
type BackendConfig struct {
	// HTTPPort is the port the backend's HTTP server listens on.
	// Default 8080.
	HTTPPort int

	// PgDSN is a libpq connection string for the aggregate's database
	// (typically the result of supervisor.Postgres.DSN("aatu_main")).
	PgDSN string

	// TemporalHostPort is host:port of the Temporal frontend gRPC.
	TemporalHostPort string

	// KeycloakIssuer is the OIDC issuer URL the realm is expected to publish.
	// At start, Backend fetches .well-known/openid-configuration and asserts
	// the issuer field matches — proves Keycloak is up AND the realm exists.
	KeycloakIssuer string
}

// Backend is the in-process aatu backend. Today it is a placeholder:
//
//   - At Start, it validates every dependency is reachable (Pg ping, Temporal
//     CheckHealth, Keycloak OIDC discovery with issuer match).
//   - It runs an HTTP server with /healthz (binary liveness) and /status
//     (JSON rollup over the entire supervisor's components).
//
// Phase A.4 (aggregate), A.5 (authz middleware), A.6 (HTTP+WS server), A.7
// (Temporal worker) replace the placeholder bodies with the real engine.
// The supervisor lifecycle around Backend stays the same throughout.
type Backend struct {
	cfg BackendConfig
	sup *Supervisor

	mu      sync.Mutex
	srv     *http.Server
	started bool
}

// NewBackend constructs the Backend component (not yet started). The
// supervisor reference is used so the /status endpoint can roll up the
// health of every other registered component.
func NewBackend(cfg BackendConfig, sup *Supervisor) *Backend {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	return &Backend{cfg: cfg, sup: sup}
}

// Name returns "backend".
func (b *Backend) Name() string { return "backend" }

// Start probes each dependency in turn and then launches the HTTP server.
// Returns the first probe error encountered without starting the server.
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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", b.handleHealthz)
	mux.HandleFunc("/status", b.handleStatus)

	addr := fmt.Sprintf("localhost:%d", b.cfg.HTTPPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	b.mu.Lock()
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
	b.mu.Unlock()

	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// Health reports whether the HTTP server is up. The richer "are all the deps
// healthy" view comes from /status (which calls into the supervisor's Health
// rollup of every component including Backend itself).
func (b *Backend) Health(_ context.Context) HealthStatus {
	b.mu.Lock()
	started := b.started
	b.mu.Unlock()
	if !started {
		return HealthStatus{Ready: false, Message: "not started"}
	}
	return HealthStatus{Ready: true, Message: fmt.Sprintf("http :%d", b.cfg.HTTPPort)}
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
	url := b.cfg.KeycloakIssuer + "/.well-known/openid-configuration"
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

// --- HTTP handlers -----------------------------------------------------------

func (b *Backend) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintln(w, "ok")
}

// StatusResponse is the JSON shape served by /status — and the same shape
// `aatu status` consumes.
type StatusResponse struct {
	Overall    string                    `json:"overall"`
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
