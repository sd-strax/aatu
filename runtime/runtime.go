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
	"time"

	_ "github.com/lib/pq" // registers the "postgres" sql driver for the aggregate DB

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/archive"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/server"
	"github.com/sd-strax/reckon/supervisor"
	"github.com/sd-strax/reckon/telemetry"
	"github.com/sd-strax/reckon/temporal"
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

	// Running without a config file means running on the SHARED fixed identity
	// namespace — deterministic STIX ids minted now will diverge from those a
	// later `init` (fresh namespace) produces for the same entities. Surface it
	// loudly rather than let the namespace switch silently mid-install.
	if p, perr := config.DefaultPath(); perr == nil {
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			log.Printf("WARN: no config at %s — running on defaults with the shared fixed identity namespace; run `%s init` first so this install gets its own immutable namespace", p, branding.CLI)
		}
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
	// Bring observability up first so everything below logs through the
	// configured structured logger and can emit spans (A.8).
	logDir := ""
	if cfg.Telemetry.LogToFile {
		logDir = telemetry.DefaultLogDir(cfg.Data.Dir)
	}
	tel, err := telemetry.Setup(telemetry.Config{
		ServiceName:    branding.CLI,
		LogLevel:       cfg.Telemetry.LogLevel,
		LogFormat:      cfg.Telemetry.LogFormat,
		LogDir:         logDir,
		MetricsEnabled: cfg.Telemetry.MetricsEnabled,
	})
	if err != nil {
		return fmt.Errorf("init telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(shutdownCtx)
	}()

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

	// Open the aggregate's DB lazily — sql.Open doesn't actually connect until
	// first query, so it's safe to construct before Pg starts. The Backend's
	// probe verifies reachability before the HTTP server accepts traffic.
	aggDB, err := sql.Open("postgres", pg.DSN("reckon_main"))
	if err != nil {
		return fmt.Errorf("open aggregate db: %w", err)
	}
	defer aggDB.Close()
	handler := aggregate.NewHandler(aggregate.NewStore(aggDB),
		aggregate.InvestigationCurrentProjector{},
		aggregate.ActionCurrentProjector{},
		aggregate.ReasoningNodeProjector{},
	).WithSideStore(aggregate.NewSideStore(aggDB))

	// The knowledge service uses its own database (reckon_knowledge); open it
	// lazily like the aggregate DB. Migrations are applied by the supervisor's
	// Postgres component per-database.
	knowledgeDB, err := sql.Open("postgres", pg.DSN("reckon_knowledge"))
	if err != nil {
		return fmt.Errorf("open knowledge db: %w", err)
	}
	defer knowledgeDB.Close()
	knowledgeStore := knowledge.NewStore(knowledgeDB)

	// The Temporal worker runs in-process (05 §3.3): it registers the OSS
	// workflow inventory on the `reckon` task queue and — when write bindings
	// are configured — the ActionLifecycle activities (handler + action
	// resolver), so the dispatch workflow (C.4) can run.
	worker := temporal.NewWorker(temporal.WorkerConfig{
		HostPort:  fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		Namespace: cfg.Temporal.Namespace,
	})
	activities, err := buildActionActivities(cfg, handler)
	if err != nil {
		return err
	}
	if activities != nil {
		worker.WithActivities(activities)
		log.Printf("%s: action-lifecycle activities registered on the worker", branding.CLI)
	}
	archiveActivities, err := buildArchiveActivities(cfg, handler)
	if err != nil {
		return err
	}
	worker.WithArchiveActivities(archiveActivities)

	sup := supervisor.New()
	sup.Register(pg, supervisor.FatalOnExit)
	sup.Register(temp, supervisor.RestartOnExit)
	sup.Register(kc, supervisor.RestartOnExit)
	sup.Register(worker, supervisor.RestartOnExit)

	// Build the read-side capability layer when a tenant capability config is
	// set (Phase B). Optional in v0: absent config leaves the /api/capabilities
	// route disabled; a present-but-broken config fails boot loudly.
	capResolver, capCatalog, err := buildCapability(cfg)
	if err != nil {
		return err
	}

	// The write-side authorization path (Phase C): Gate 2 + the action catalog
	// enable the request_action route.
	gate2, actionCatalog, err := buildGate2(cfg)
	if err != nil {
		return err
	}

	backendCfg := server.BackendConfig{
		HTTPPort:         cfg.Backend.HTTPPort,
		PgDSN:            pg.DSN("reckon_main"),
		TemporalHostPort: fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		KeycloakIssuer: fmt.Sprintf("http://localhost:%d/realms/%s",
			cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm),
		KeycloakClientID:   cfg.Keycloak.ClientID,
		Handler:            handler,
		Middleware:         tel.HTTPMiddleware,
		CapabilityResolver: capResolver,
		CapabilityCatalog:  capCatalog,
		Gate2:              gate2,
		ActionCatalog:      actionCatalog,
		Knowledge:          knowledgeStore,
	}
	if tel.Metrics != nil {
		backendCfg.MetricsHandler = tel.Metrics.Handler()
	}
	backend := server.NewBackend(backendCfg, sup)
	sup.Register(backend, supervisor.RestartOnExit)

	log.Printf("%s: pid %d; /status on http://localhost:%d/status; %s stop to shut down",
		branding.CLI, os.Getpid(), cfg.Backend.HTTPPort, branding.CLI)

	if err := sup.Run(ctx); err != nil {
		return fmt.Errorf("supervisor: %w", err)
	}
	log.Printf("%s: stopped", branding.CLI)
	return nil
}

// buildGate2 constructs the Gate 2 engine (baseline DENY + any tenant policies)
// and the action catalog, enabling the request_action route. Returns
// (nil, nil, nil) when no capability config is set — the action layer is off.
func buildGate2(cfg config.Config) (*action.Gate2, *action.ActionCatalog, error) {
	if cfg.Capability.ConfigPath == "" {
		return nil, nil, nil
	}
	var policies []action.Policy
	if dir := cfg.Capability.PolicyDir; dir != "" {
		p, err := action.LoadPolicies(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("load Gate 2 policies: %w", err)
		}
		policies = p
	}
	gate2, err := action.NewGate2(policies)
	if err != nil {
		return nil, nil, fmt.Errorf("build Gate 2: %w", err)
	}
	return gate2, action.DefaultActionCatalog(), nil
}

// buildActionActivities constructs the ActionLifecycle activities (aggregate
// handler + write-side action resolver) from the tenant config, or nil when no
// write bindings are configured. Reuses the capability config path — the
// action_adapters/action_bindings keys can share the same file (08 §4).
func buildActionActivities(cfg config.Config, handler *aggregate.Handler) (*temporal.Activities, error) {
	path := cfg.Capability.ConfigPath
	if path == "" {
		return nil, nil
	}
	ac, err := action.LoadActionConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load action config: %w", err)
	}
	if len(ac.Bindings) == 0 {
		return nil, nil // no write bindings — workflows-only worker
	}
	resolver, _, err := action.BuildActionResolver(ac, cfg.Capability.FixtureRoot)
	if err != nil {
		return nil, fmt.Errorf("build action resolver: %w", err)
	}
	return temporal.NewActivities(handler, resolver), nil
}

// buildArchiveActivities constructs the post-conclusion export activities: the
// aggregate handler (event store + projections), the tenant signing key (07
// §2.2, loaded/created under <data>/keys), and the archive root (07 §2.4 solo
// default <data>/archive). Unlike the action activities, these need no tenant
// config — every deployment can export.
func buildArchiveActivities(cfg config.Config, handler *aggregate.Handler) (*temporal.ArchiveActivities, error) {
	signer, err := archive.LoadOrCreateSigner(filepath.Join(cfg.Data.Dir, "keys", "signing.ed25519"))
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	archiveDir := filepath.Join(cfg.Data.Dir, "archive")
	return temporal.NewArchiveActivities(handler, signer, archiveDir), nil
}

// buildCapability constructs the capability resolver + catalog from the tenant
// capability config, or returns (nil, nil, nil) when no config path is set. A
// present-but-malformed config is a boot error — the operator asked for it.
func buildCapability(cfg config.Config) (*capability.Resolver, *capability.Catalog, error) {
	path := cfg.Capability.ConfigPath
	if path == "" {
		return nil, nil, nil
	}
	tc, err := capability.LoadTenantConfig(path)
	if err != nil {
		return nil, nil, err
	}
	ns, err := uuid.Parse(cfg.Capability.TenantNamespace)
	if err != nil {
		return nil, nil, fmt.Errorf("capability.tenant_namespace %q: %w", cfg.Capability.TenantNamespace, err)
	}
	resolver, catalog, err := capability.BuildResolver(tc, cfg.Capability.FixtureRoot, ns)
	if err != nil {
		return nil, nil, fmt.Errorf("build capability layer: %w", err)
	}
	log.Printf("%s: capability layer loaded from %s (%d verbs available)",
		branding.CLI, path, len(resolver.AvailableVerbs(catalog)))
	return resolver, catalog, nil
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
