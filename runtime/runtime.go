package runtime

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/lib/pq" // registers the "postgres" sql driver for the aggregate DB

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/server"
	"github.com/sd-strax/reckon/supervisor"
)

// Config is the runtime configuration passed to a ModuleBuilder. Today it
// is the full deployment config; a future refactor may split runtime-only
// concerns (logging, metrics, supervisor options) from the deployment shape.
type Config = config.Config

// ModuleBuilder constructs the module Registry from a loaded Config.
//
// Both binaries inject one. The OSS binary returns disabled stubs
// unconditionally; the paid binary inspects cfg.Paid.* and returns real
// implementations when enabled, stubs when not. This closure is the only place
// where OSS and paid main packages diverge — everything below this line is
// shared by importing.
type ModuleBuilder func(Config) module.Registry

// Run is the shared backend entry point. It activates the module registry (the
// OSS/paid seam) and then boots the bundled stack, blocking until shutdown
// (signal, fatal component exit, or restart-budget exhaustion).
//
// Both the OSS and paid binaries call Run with their own ModuleBuilder; the
// builder is their only divergence. This is the architectural enforcement of
// "paid layers on OSS, no overlap": the paid binary cannot boot the stack any
// differently than OSS, because the boot path lives here, not in either main.
func Run(build ModuleBuilder) error {
	cfg, _, err := activate(build)
	if err != nil {
		return err
	}
	// The activated registry currently feeds only activate's logging; it
	// threads into serve as the injection point for tenancy/governance wiring
	// into the Backend once those modules are consumed (a later phase).
	return serve(cfg)
}

// Preflight runs the activation seam — load config, build the registry, log the
// activation shape — without starting any services, then returns. It backs the
// `check` command and the A.1 architectural-seam test: a fast, dependency-free
// proof that the paid.* flags flip modules on and off.
func Preflight(build ModuleBuilder) error {
	_, _, err := activate(build)
	return err
}

// activate loads configuration and builds the module registry, logging the
// resulting activation shape and warning when paid.* is requested against a
// binary with no paid module. Shared by Run (before boot) and Preflight.
func activate(build ModuleBuilder) (config.Config, module.Registry, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, module.Registry{}, fmt.Errorf("load config: %w", err)
	}

	reg := build(cfg)

	// Warn if paid keys are set but the registry has no real paid module —
	// this is an OSS binary running against a config that wants paid behavior.
	if cfg.Paid.Tenancy.Enabled && !reg.Tenancy.Enabled() {
		log.Println("WARN: paid.tenancy.enabled set but no paid tenancy module loaded (OSS binary)")
	}
	if cfg.Paid.Governance.Enabled && !reg.Governance.Enabled() {
		log.Println("WARN: paid.governance.enabled set but no paid governance module loaded (OSS binary)")
	}

	log.Printf("%s engine ready, tenancy=%v governance=%v",
		branding.CLI, reg.Tenancy.Enabled(), reg.Governance.Enabled())
	return cfg, reg, nil
}

// serve assembles the bundled-deps supervisor (Postgres, Temporal, Keycloak)
// and the in-process Backend, then runs the supervisor until shutdown. The PID
// file is written on entry and removed on exit so `reckon stop` can find the
// process.
func serve(cfg config.Config) error {
	pidPath := PIDFilePath(cfg)
	if err := writePIDFile(pidPath); err != nil {
		return err
	}
	defer func() { _ = os.Remove(pidPath) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pg := supervisor.NewPostgres(supervisor.PostgresConfig{
		DataDir: filepath.Join(cfg.Data.Dir, "pg"),
		Port:    cfg.Postgres.Port,
		// Temporal manages its own SQLite store (see D15) so there's no
		// reckon_temporal database here today.
		Databases: []supervisor.DatabaseSpec{
			{Name: "reckon_main", Migrations: aggregate.Migrations()},
			{Name: "reckon_knowledge", Migrations: knowledge.Migrations()},
		},
	})
	temp := supervisor.NewTemporal(supervisor.TemporalConfig{
		DataDir:      filepath.Join(cfg.Data.Dir, "temporal"),
		FrontendPort: cfg.Temporal.FrontendPort,
		EnableUI:     cfg.Temporal.UIEnabled,
		UIPort:       cfg.Temporal.UIPort,
		Namespace:    cfg.Temporal.Namespace,
	})
	kc := supervisor.NewKeycloak(supervisor.KeycloakConfig{
		DataDir:        filepath.Join(cfg.Data.Dir, "keycloak"),
		HTTPPort:       cfg.Keycloak.HTTPPort,
		ManagementPort: cfg.Keycloak.ManagementPort,
		RealmName:      cfg.Keycloak.Realm,
	})

	sup := supervisor.New()
	sup.Register(pg, supervisor.FatalOnExit)
	sup.Register(temp, supervisor.RestartOnExit)
	sup.Register(kc, supervisor.RestartOnExit)

	// Open the aggregate's DB lazily — sql.Open doesn't actually connect
	// until first query, so it's safe to construct before Pg starts. The
	// Backend's probe verifies reachability before the HTTP server accepts
	// traffic.
	aggDB, err := sql.Open("postgres", pg.DSN("reckon_main"))
	if err != nil {
		return fmt.Errorf("open aggregate db: %w", err)
	}
	defer aggDB.Close()
	handler := aggregate.NewHandler(aggregate.NewStore(aggDB),
		aggregate.InvestigationCurrentProjector{},
	)

	backend := server.NewBackend(server.BackendConfig{
		HTTPPort:         cfg.Backend.HTTPPort,
		PgDSN:            pg.DSN("reckon_main"),
		TemporalHostPort: fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		KeycloakIssuer: fmt.Sprintf("http://localhost:%d/realms/%s",
			cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm),
		Handler: handler,
	}, sup)
	sup.Register(backend, supervisor.RestartOnExit)

	log.Printf("%s: pid %d; /status on http://localhost:%d/status; %s stop to shut down",
		branding.CLI, os.Getpid(), cfg.Backend.HTTPPort, branding.CLI)

	if err := sup.Run(ctx); err != nil {
		return fmt.Errorf("supervisor: %w", err)
	}
	log.Printf("%s: stopped", branding.CLI)
	return nil
}

// PIDFilePath returns the supervisor PID-file path for this config. serve
// writes it; `reckon stop` reads it.
func PIDFilePath(cfg config.Config) string {
	return filepath.Join(cfg.Data.Dir, branding.PidName)
}

// writePIDFile records this process's PID so `reckon stop` can find it. If an
// existing PID file points at a live process, it refuses to overwrite —
// protecting against accidentally running two supervisors.
func writePIDFile(path string) error {
	if data, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && isProcessAlive(pid) {
			return fmt.Errorf("another supervisor (pid %d) is running; stop it first with `%s stop`, or remove %s if you know it's stale",
				pid, branding.CLI, path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644)
}

// isProcessAlive probes via Signal(0) — the canonical Unix way to test whether
// a PID is a live process.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
