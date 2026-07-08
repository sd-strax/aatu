package supervisor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	"github.com/sd-strax/reckon/internal/branding"
)

// TemporalConfig configures the bundled Temporal dev server.
type TemporalConfig struct {
	// DataDir is the root directory for Temporal state.
	// Subdirs: bin/ (cached CLI binary), data.sqlite (durable store).
	DataDir string

	// FrontendPort is the gRPC port the dev-server frontend listens on.
	// Default 7233 (Temporal's standard).
	FrontendPort int

	// EnableUI controls whether the Temporal web UI is started.
	// Default true (the UI is invaluable for workflow debugging).
	EnableUI bool

	// UIPort is the HTTP port for the web UI when EnableUI is true.
	// Default 8233.
	UIPort int

	// Namespace is the default Temporal namespace pre-registered at startup.
	// Default "default".
	Namespace string
}

// Temporal wraps the Temporal CLI dev server. The dev server is SQLite-backed
// — a deliberate deviation from the spec's "Postgres-backed dev mode" framing.
// SQLite is fine for OSS solo / dev; deployments that need scale use managed
// Temporal Cloud or a self-hosted cluster and don't bring up Temporal via
// this supervisor at all.
type Temporal struct {
	cfg TemporalConfig

	mu     sync.Mutex // guards server; Health runs concurrently with watcher Stop/Start
	server *testsuite.DevServer
}

// NewTemporal constructs the Temporal component (not yet started).
// Defaults: FrontendPort=7233, EnableUI=true, UIPort=8233, Namespace="default",
// DataDir=$HOME/<branding.DataDir>/temporal.
func NewTemporal(cfg TemporalConfig) *Temporal {
	if cfg.FrontendPort == 0 {
		cfg.FrontendPort = 7233
	}
	if cfg.UIPort == 0 {
		cfg.UIPort = 8233
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if cfg.DataDir == "" {
		home, _ := os.UserHomeDir()
		cfg.DataDir = filepath.Join(home, branding.DataDir, "temporal")
	}
	return &Temporal{cfg: cfg}
}

// Name returns "temporal".
func (t *Temporal) Name() string { return "temporal" }

// Start downloads (first run) and starts the Temporal CLI dev server, pre-
// registering the configured namespace and binding the frontend to the
// configured port.
func (t *Temporal) Start(ctx context.Context) error {
	if err := os.MkdirAll(t.cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create temporal data dir: %w", err)
	}
	binDir := filepath.Join(t.cfg.DataDir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return fmt.Errorf("create temporal bin dir: %w", err)
	}
	dbPath := filepath.Join(t.cfg.DataDir, "data.sqlite")

	opts := testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{
			DestDir: binDir,
		},
		ClientOptions: &client.Options{
			HostPort:  fmt.Sprintf("localhost:%d", t.cfg.FrontendPort),
			Namespace: t.cfg.Namespace,
		},
		DBFilename: dbPath,
		EnableUI:   t.cfg.EnableUI,
		LogLevel:   "warn",
	}
	if t.cfg.EnableUI {
		opts.UIPort = fmt.Sprintf("%d", t.cfg.UIPort)
	}

	server, err := testsuite.StartDevServer(ctx, opts)
	if err != nil {
		return fmt.Errorf("start temporal dev server: %w", err)
	}
	t.mu.Lock()
	t.server = server
	t.mu.Unlock()
	return nil
}

// Stop the dev server. Idempotent — multiple calls return nil.
func (t *Temporal) Stop(_ context.Context) error {
	t.mu.Lock()
	server := t.server
	t.server = nil
	t.mu.Unlock()
	if server == nil {
		return nil
	}
	if err := server.Stop(); err != nil {
		return fmt.Errorf("stop temporal: %w", err)
	}
	return nil
}

// Health probes the dev server's frontend port with a short TCP dial. A
// crashed dev-server process must report not-ready here, or the watcher's
// RestartOnExit policy never fires — "started once" is not liveness.
func (t *Temporal) Health(ctx context.Context) HealthStatus {
	hostPort := t.FrontendHostPort()
	if hostPort == "" {
		return HealthStatus{Ready: false, Message: "not started"}
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return HealthStatus{Ready: false, Message: fmt.Sprintf("frontend %s unreachable: %v", hostPort, err)}
	}
	_ = conn.Close()
	return HealthStatus{
		Ready:   true,
		Message: fmt.Sprintf("frontend %s, namespace %s", hostPort, t.cfg.Namespace),
	}
}

// FrontendHostPort returns the host:port string of the dev server's frontend
// (e.g., "localhost:7233"). Useful for downstream consumers (workers, the
// reckon-backend) to construct Temporal clients without re-deriving from config.
// Empty until Start has succeeded.
func (t *Temporal) FrontendHostPort() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.server == nil {
		return ""
	}
	return t.server.FrontendHostPort()
}

// Namespace returns the configured Temporal namespace.
func (t *Temporal) Namespace() string {
	return t.cfg.Namespace
}
