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
	"github.com/sd-strax/reckon/comms"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/secretref"
	"github.com/sd-strax/reckon/internal/secrets"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/knowledge/substrate"
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
// requireSecret resolves an install secret with precedence env → store, failing
// fast when neither provides it. The env override is the operator/vault path
// (nothing on disk); the store is the deployer-provisioned default.
func requireSecret(store *secrets.Store, envVar, name, label string) (string, error) {
	v, ok, err := store.Resolve(envVar, name)
	if err != nil {
		return "", fmt.Errorf("read %s secret: %w", label, err)
	}
	if !ok {
		return "", fmt.Errorf("%s secret not provisioned — run `%s init` first, or inject %s (the operator/vault path)", label, branding.CLI, envVar)
	}
	return v, nil
}

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

	// The operator step only consumes secrets — it never mints them. The
	// Postgres role password and the Keycloak master-admin password are
	// provisioned by the deployer step (`reckon init`, runtime.provisionSecrets)
	// into the install secret store beside the config; start reads them here and
	// fails fast if the deploy step was skipped.
	configPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	store := secrets.Open(filepath.Dir(configPath))
	pgPassword, err := requireSecret(store, secrets.EnvPostgres, secrets.NamePostgres, "postgres role")
	if err != nil {
		return err
	}
	kcAdminPassword, err := requireSecret(store, secrets.EnvKeycloakAdmin, secrets.NameKeycloakAdmin, "keycloak admin")
	if err != nil {
		return err
	}

	// The binaries/data split (05 §12.4): when data.runtime_dir (or
	// $<CLI>_RUNTIME_DIR — the container image sets it) is configured, the
	// downloaded distributions live there, per component, and cfg.Data.Dir
	// holds only mutable state. Empty subdir results mean "component default".
	runtimeSub := func(name string) string {
		if cfg.Data.RuntimeDir == "" {
			return ""
		}
		return filepath.Join(cfg.Data.RuntimeDir, name)
	}

	pg := supervisor.NewPostgres(supervisor.PostgresConfig{
		DataDir:    filepath.Join(cfg.Data.Dir, "pg"),
		RuntimeDir: runtimeSub("pg"),
		Port:       cfg.Postgres.Port,
		Password:   pgPassword,
		SSLMode:    cfg.Postgres.SSLMode,
		// Temporal manages its own SQLite store (see D15) so there's no
		// reckon_temporal database here today.
		Databases: []supervisor.DatabaseSpec{
			{Name: "reckon_main", Migrations: aggregate.Migrations()},
			{
				Name:       "reckon_knowledge",
				Migrations: knowledge.Migrations(),
				// The memory substrate owns its schema (00-substrate §12) and
				// versions it independently, so it shares reckon_knowledge under
				// its own tracking table rather than colliding on version 1.
				ExtraMigrations: []supervisor.ExtraMigrationSet{
					{FS: substrate.Migrations(), Table: "substrate_schema_migrations"},
				},
			},
			// Keycloak's state database (05 §12.4: one DB engine for everything).
			// No migrations — Keycloak owns and migrates its own schema.
			{Name: "reckon_keycloak"},
		},
	})
	temp := supervisor.NewTemporal(supervisor.TemporalConfig{
		DataDir:      filepath.Join(cfg.Data.Dir, "temporal"),
		BinDir:       runtimeSub("temporal"),
		FrontendPort: cfg.Temporal.FrontendPort,
		EnableUI:     cfg.Temporal.UIEnabled,
		UIPort:       cfg.Temporal.UIPort,
		Namespace:    cfg.Temporal.Namespace,
	})
	kc := supervisor.NewKeycloak(supervisor.KeycloakConfig{
		DataDir:        filepath.Join(cfg.Data.Dir, "keycloak"),
		RuntimeDir:     runtimeSub("keycloak"),
		HTTPPort:       cfg.Keycloak.HTTPPort,
		ManagementPort: cfg.Keycloak.ManagementPort,
		RealmName:      cfg.Keycloak.Realm,
		AdminPassword:  kcAdminPassword,
		// Keycloak's state lives in the supervised Postgres (05 §12.4) — same
		// instance, same role, its own database (created by pg above).
		DBPort:     pg.Port(),
		DBPassword: pgPassword,
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
		aggregate.VerdictPinProjector{},
		aggregate.RefAppearanceProjector{},
	).WithSideStore(aggregate.NewSideStore(aggDB))

	// The knowledge service uses its own database (reckon_knowledge); open it
	// lazily like the aggregate DB. Migrations are applied by the supervisor's
	// Postgres component per-database.
	knowledgeDB, err := sql.Open("postgres", pg.DSN("reckon_knowledge"))
	if err != nil {
		return fmt.Errorf("open knowledge db: %w", err)
	}
	defer knowledgeDB.Close()
	knowledgeStore, err := buildKnowledge(cfg, knowledgeDB)
	if err != nil {
		return fmt.Errorf("build knowledge service: %w", err)
	}

	// The out-of-process adapter host (Phase E, 11 §2) scans <data>/adapters and
	// owns one plugin process per enabled instance, shared across the read
	// resolver, both action resolvers, and the worker — so a vendor serving both
	// reads and writes runs as one process, not two (11 §8). Spawn is lazy:
	// nothing starts until a verb/action resolves to a plugin binding. An absent
	// or empty dir means no plugins, and the fixture path is untouched. It uses
	// the global slog logger installed by telemetry.Setup.
	adapterHost := adapterplugin.NewHost(filepath.Join(cfg.Data.Dir, "adapters"), branding.CLI+" engine", nil)
	defer adapterHost.Close()
	for _, p := range adapterHost.Problems() {
		log.Printf("%s: adapter install skipped — %s", branding.CLI, p)
	}

	// The Temporal worker runs in-process (05 §3.3): it registers the OSS
	// workflow inventory on the `reckon` task queue and — when write bindings
	// are configured — the ActionLifecycle activities (handler + action
	// resolver), so the dispatch workflow (C.4) can run.
	worker := temporal.NewWorker(temporal.WorkerConfig{
		HostPort:  fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		Namespace: cfg.Temporal.Namespace,
	})
	// The comms-thread store (Phase F, binding §4) rides the main DB: the
	// result path opens threads for SUCCEEDED notify.* dispatches, and the
	// backend serves/acts on them.
	commsStore := comms.NewStore(handler.DB())
	activities, dispatchResolver, err := buildActionActivities(cfg, handler, commsStore, adapterHost)
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
	// K3: the post-conclusion summarizer writes into the knowledge substrate's
	// DERIVED case-summaries corpus (the same store SOPs use).
	worker.WithSummaryActivities(temporal.NewSummaryActivities(handler, knowledgeStore))

	sup := supervisor.New()
	sup.Register(pg, supervisor.FatalOnExit)
	sup.Register(temp, supervisor.RestartOnExit)
	sup.Register(kc, supervisor.RestartOnExit)
	sup.Register(worker, supervisor.RestartOnExit)

	// Build the read-side capability layer when a tenant capability config is
	// set (Phase B). Optional in v0: absent config leaves the /api/capabilities
	// route disabled; a present-but-broken config fails boot loudly.
	capResolver, capCatalog, err := buildCapability(cfg, adapterHost)
	if err != nil {
		return err
	}

	// The write-side authorization path (Phase C): Gate 2 + the action catalog
	// enable the request_action route.
	gate2, actionCatalog, err := buildGate2(cfg)
	if err != nil {
		return err
	}

	// The action resolver backs GET /api/action-types (the agent's write-side
	// catalog with per-type dispatchability). Built whenever the action layer is
	// on, independent of whether write bindings exist (zero bindings → every
	// type reports unavailable, which is the honest answer).
	actionResolver, err := buildBackendActionResolver(cfg, adapterHost)
	if err != nil {
		return err
	}

	backendCfg := server.BackendConfig{
		HTTPPort:         cfg.Backend.HTTPPort,
		PgDSN:            pg.DSN("reckon_main"),
		TemporalHostPort: fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		KeycloakIssuer: fmt.Sprintf("http://localhost:%d/realms/%s",
			cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm),
		KeycloakClientID: cfg.Keycloak.ClientID,
		// The interactive human login client is the realm's public "reckon"
		// client (keycloak_realm.json); branding.CLI is that literal, kept in
		// one place so a rebrand doesn't drift the realm from the code. The
		// agent client is its delegate-path sibling ("reckon-agent", the one
		// with the delegate_kind mapper) — advertised so surfaces discover it
		// instead of hardcoding the suffix convention.
		KeycloakLoginClientID: branding.CLI,
		KeycloakAgentClientID: branding.CLI + "-agent",
		Handler:               handler,
		Middleware:            tel.HTTPMiddleware,
		CapabilityResolver:    capResolver,
		CapabilityCatalog:     capCatalog,
		// The enablement surface (11 §5.1) edits the same file the resolver
		// was built from and rebuilds it in place.
		CapabilityConfigPath:  cfg.Capability.ConfigPath,
		CapabilityFixtureRoot: cfg.Capability.FixtureRoot,
		// The no-restart reload closure: re-run the full plugin build path
		// (adapter host + out-of-process adapters + catalog reconciliation).
		// Injected here because only runtime holds adapterHost.
		CapabilityRebuild: func() (*capability.Resolver, *capability.Catalog, error) {
			return buildCapability(cfg, adapterHost)
		},
		Gate2:          gate2,
		ActionCatalog:  actionCatalog,
		ActionResolver: actionResolver,
		Knowledge:      knowledgeStore,
		Comms:          commsStore,

		TenantNamespace:         cfg.Capability.TenantNamespace,
		ExportIncludeSideStores: cfg.Export.IncludeSideStores,
		ExportAutoOnConclude:    cfg.Export.AutoOnConclude,
		AllowAIVerdict:          cfg.Trust.AIVerdict,
		AllowAIReasoning:        cfg.Trust.AIReasoning,
	}
	if tel.Metrics != nil {
		backendCfg.MetricsHandler = tel.Metrics.Handler()
	}
	backend := server.NewBackend(backendCfg, sup)
	sup.Register(backend, supervisor.RestartOnExit)

	// SIGHUP is the no-restart reload (11 §5.1): `reckon adapter setup`/`reload`
	// signals the running supervisor after editing the tenant config, and both
	// the read layer AND the write-dispatch resolver rebuild in place —
	// Postgres/Temporal/Keycloak never bounce because a YAML file changed. The
	// write swap covers even enabling the first write adapter, because the
	// worker always registers the action activities when the action layer is
	// configured (buildActionActivities); the one case still needing a restart
	// is turning the action layer on from a config that had no path at all.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				// Pick up adapters installed since boot (or since the last
				// reload): `adapter setup <new adapter>` signals HUP right after
				// installing, and the host's scan-once cache would otherwise
				// leave the new install invisible until a restart.
				for _, p := range adapterHost.Rescan() {
					log.Printf("%s: adapter scan: %s: %s", branding.CLI, p.Dir, p.Message)
				}
				// Reads: rebuild + swap the capability surface.
				if err := backend.ReloadCapability(); err != nil {
					log.Printf("%s: capability reload failed (running surface unchanged): %v", branding.CLI, err)
				} else {
					log.Printf("%s: capability layer reloaded from %s", branding.CLI, cfg.Capability.ConfigPath)
				}
				// Writes: rebuild the action resolver once, swap it into both the
				// worker's dispatch path and the backend's /action-types readout.
				if dispatchResolver != nil {
					newAR, aerr := buildActionResolverFromFile(cfg, adapterHost)
					if aerr != nil {
						log.Printf("%s: action reload failed (running dispatch unchanged): %v", branding.CLI, aerr)
					} else {
						dispatchResolver.Store(newAR)
						backend.SetActionResolver(newAR)
						log.Printf("%s: action-dispatch layer reloaded", branding.CLI)
					}
				}
			}
		}
	}()

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

// buildKnowledge constructs the SOP knowledge store over the memory substrate.
// The substrate declares reckon's two corpora and, when embeddings are
// configured, gets the OpenAI-compatible embedder for semantic recall. The
// secret reference is resolved here at the composition root, so the substrate
// only ever receives a constructed Embedder with a resolved literal — config
// reading and secret resolution stay host concerns (00-substrate §12). With no
// embeddings configured the substrate runs its attributed keyword fallback.
func buildKnowledge(cfg config.Config, db *sql.DB) (*knowledge.Store, error) {
	corpora := []substrate.CorpusDef{
		{Name: knowledge.CorpusProcedures, Archetype: substrate.Curated, Governance: substrate.Lightweight},
		{Name: knowledge.CorpusCaseSummaries, Archetype: substrate.Derived},
	}
	var opts []substrate.Option
	if emb := cfg.Knowledge.Embeddings; emb.BaseURL != "" {
		if emb.Model == "" {
			return nil, fmt.Errorf("knowledge.embeddings: model is required when base_url is set")
		}
		key, err := resolveEmbeddingKey(emb.APIKey)
		if err != nil {
			return nil, err
		}
		embedder, err := substrate.NewOpenAICompatEmbedder(emb.BaseURL, key, emb.Model, nil)
		if err != nil {
			return nil, fmt.Errorf("knowledge.embeddings: %w", err)
		}
		opts = append(opts, substrate.WithEmbedder(embedder))
		log.Printf("%s: knowledge semantic recall via %s (model %s)", branding.CLI, emb.BaseURL, emb.Model)
	} else {
		log.Printf("%s: knowledge embeddings not configured — recall runs the keyword fallback", branding.CLI)
	}
	store, err := substrate.NewPostgres(db, corpora, opts...)
	if err != nil {
		return nil, fmt.Errorf("construct substrate: %w", err)
	}
	return knowledge.NewStore(store), nil
}

// resolveEmbeddingKey resolves the embeddings API key. Empty is allowed (self-
// hosted endpoints that need no auth); a non-empty value must be a secret
// REFERENCE, never a literal — resolved here so plaintext never sits in config
// or reaches the substrate.
func resolveEmbeddingKey(ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if !secretref.IsRef(ref) {
		return "", fmt.Errorf("knowledge.embeddings.api_key must be a secret reference (keychain:// / env:// / vault://), not a literal")
	}
	key, err := secretref.Resolve(ref)
	if err != nil {
		return "", fmt.Errorf("resolve knowledge.embeddings.api_key: %w", err)
	}
	return key, nil
}

// buildBackendActionResolver builds the write-side action resolver for the
// backend's GET /api/action-types endpoint. Unlike buildActionActivities (which
// returns nil with no bindings, since a worker with nothing to dispatch is
// pointless), this returns a resolver whenever the action layer is configured —
// a resolver with zero bindings simply reports every action type as
// unavailable, which is the honest catalog view the agent needs. Returns nil
// when the action layer is off (no config path).
func buildBackendActionResolver(cfg config.Config, host *adapterplugin.Host) (*action.ActionResolver, error) {
	if cfg.Capability.ConfigPath == "" {
		return nil, nil
	}
	ac, err := action.LoadActionConfig(cfg.Capability.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load action config: %w", err)
	}
	plugins, err := pluginWriteAdapters(host, ac)
	if err != nil {
		return nil, err
	}
	resolver, _, err := action.BuildActionResolverWithAdapters(ac, cfg.Capability.FixtureRoot, plugins)
	if err != nil {
		return nil, fmt.Errorf("build action resolver: %w", err)
	}
	return resolver, nil
}

// buildActionActivities constructs the ActionLifecycle activities (aggregate
// handler + write-side action resolver) from the tenant config, or nil when no
// write bindings are configured. Reuses the capability config path — the
// action_adapters/action_bindings keys can share the same file (08 §4).
func buildActionActivities(cfg config.Config, handler *aggregate.Handler, commsStore *comms.Store, host *adapterplugin.Host) (*temporal.Activities, *action.AtomicResolver, error) {
	if cfg.Capability.ConfigPath == "" {
		return nil, nil, nil // action layer off entirely
	}
	// Build the resolver even with zero write bindings, and register the
	// activities regardless: the worker cannot register after start, so
	// always-registering is what lets a later reload (11 §5.1) enable the FIRST
	// write adapter without a restart. A zero-binding resolver is harmless —
	// Resolve yields ErrNoBinding, and nothing triggers dispatch without a
	// binding anyway.
	resolver, err := buildActionResolverFromFile(cfg, host)
	if err != nil {
		return nil, nil, err
	}
	holder := action.NewAtomicResolver(resolver)
	return temporal.NewActivities(handler, holder, commsStore), holder, nil
}

// buildActionResolverFromFile builds the write-side action resolver from the
// tenant config on disk (the raw resolver, shared by the worker's dispatch
// holder and the backend's /action-types readout). Returns a valid resolver
// even when there are no write bindings.
func buildActionResolverFromFile(cfg config.Config, host *adapterplugin.Host) (*action.ActionResolver, error) {
	ac, err := action.LoadActionConfig(cfg.Capability.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load action config: %w", err)
	}
	plugins, err := pluginWriteAdapters(host, ac)
	if err != nil {
		return nil, err
	}
	resolver, _, err := action.BuildActionResolverWithAdapters(ac, cfg.Capability.FixtureRoot, plugins)
	if err != nil {
		return nil, fmt.Errorf("build action resolver: %w", err)
	}
	return resolver, nil
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
func buildCapability(cfg config.Config, host *adapterplugin.Host) (*capability.Resolver, *capability.Catalog, error) {
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
	plugins, err := pluginReadAdapters(host, tc)
	if err != nil {
		return nil, nil, err
	}
	resolver, catalog, err := capability.BuildResolverWithAdapters(tc, cfg.Capability.FixtureRoot, ns, plugins)
	if err != nil {
		return nil, nil, fmt.Errorf("build capability layer: %w", err)
	}
	// Register the verbs an out-of-process adapter describes but the engine
	// catalog does not already define (11 §4.2), so an adapter's own verbs are
	// visible to the agent — without this, only DefaultCatalog verbs surface.
	reconcileCatalog(host, tc, catalog)
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
