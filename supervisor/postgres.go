package supervisor

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"

	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/pgmigrate"
)

// PostgresConfig configures the bundled Postgres instance.
type PostgresConfig struct {
	// DataDir is the root directory for Pg state.
	// Subdirs created on first start: data/ (Pg cluster), runtime/ (per-boot
	// scratch — the embedded library wipes and repopulates it every start).
	DataDir string

	// RuntimeDir optionally holds the immutable Pg distribution separately from
	// DataDir's mutable state — the binaries/data split (05 §12.4). When set,
	// the extracted binaries live at RuntimeDir/binaries (extraction is skipped
	// when they are already present — the baked-image path) and the downloaded
	// archive at RuntimeDir/cache. Empty keeps today's behavior: everything
	// under DataDir plus the embedded library's default archive cache.
	RuntimeDir string

	// Port is the TCP port Pg listens on. Default 5435 to avoid collision
	// with a system Pg on the default 5432.
	Port uint32

	// Password is the `reckon` role's password — a provisioned install secret
	// (internal/secrets), injected by runtime. Required; Start fails without it.
	// The component consumes it, never hardcodes it.
	Password string

	// SSLMode is the libpq sslmode used in DSNs. Default "disable" (loopback).
	SSLMode string

	// Databases to create + migrate on first start. Each spec names a
	// database and (optionally) an embedded fs.FS of SQL migrations.
	// Database creation is idempotent; migrations run on every start
	// (golang-migrate tracks applied versions in schema_migrations).
	Databases []DatabaseSpec
}

// DatabaseSpec is one database the supervisor's Postgres manages.
type DatabaseSpec struct {
	// Name is the Postgres database name. Created on first start; safe to
	// re-list on subsequent starts (CREATE DATABASE is gated on existence).
	Name string

	// Migrations is an optional fs.FS rooted at a directory of golang-migrate
	// SQL files (NNNN_label.up.sql + NNNN_label.down.sql). nil means no
	// migrations — the database is just created and left empty.
	Migrations fs.FS

	// ExtraMigrations are additional, independently-versioned migration sets
	// applied to the SAME database after Migrations, each tracked under its own
	// table — so an embedded component that owns its schema (the memory
	// substrate) can share a host database without version-number collisions.
	ExtraMigrations []ExtraMigrationSet
}

// ExtraMigrationSet is a secondary migration set on a database, tracked under
// its own golang-migrate table.
type ExtraMigrationSet struct {
	FS    fs.FS
	Table string // must be distinct from the default schema_migrations and from siblings
}

// Postgres is a Component wrapping fergusstrange/embedded-postgres.
//
// pgvector availability is a deferred concern: the vanilla embedded
// distribution does not ship pgvector. Phase G (embeddings) bundles a
// pgvector-enabled Pg or installs the .so files at first run. Until then
// the embedding-bearing tables use TEXT placeholders.
type Postgres struct {
	cfg PostgresConfig

	mu sync.Mutex // guards pg; Health runs concurrently with watcher Stop/Start
	pg *embeddedpostgres.EmbeddedPostgres
}

// NewPostgres constructs the Postgres component (not yet started).
// Defaults: Port=5435; DataDir=$HOME/<branding.DataDir>/pg.
func NewPostgres(cfg PostgresConfig) *Postgres {
	if cfg.Port == 0 {
		cfg.Port = 5435
	}
	if cfg.DataDir == "" {
		home, _ := os.UserHomeDir()
		cfg.DataDir = filepath.Join(home, branding.DataDir, "pg")
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}
	return &Postgres{cfg: cfg}
}

// Name returns "postgres".
func (p *Postgres) Name() string { return "postgres" }

// Start downloads (first run) and starts the embedded Pg process, then
// ensures every requested database exists.
func (p *Postgres) Start(ctx context.Context) error {
	if p.cfg.Password == "" {
		return fmt.Errorf("postgres: no role password provisioned (run `%s init`)", branding.CLI)
	}
	if err := os.MkdirAll(p.cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	runtimePath := filepath.Join(p.cfg.DataDir, "runtime")
	dataPath := filepath.Join(p.cfg.DataDir, "data")

	cfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(p.cfg.Port).
		RuntimePath(runtimePath).
		DataPath(dataPath).
		Database("postgres").
		Username("reckon").
		Password(p.cfg.Password) // provisioned install secret (internal/secrets)
	if p.cfg.RuntimeDir != "" {
		// Binaries/data split (05 §12.4): the distribution lives in RuntimeDir
		// (image-owned in the container shape). The library skips extraction
		// when binaries are already present, so a baked image never re-fetches;
		// RuntimePath above remains per-boot scratch under DataDir.
		cfg = cfg.
			BinariesPath(filepath.Join(p.cfg.RuntimeDir, "binaries")).
			CachePath(filepath.Join(p.cfg.RuntimeDir, "cache"))
	}

	// Build + start on a local before publishing, so Health never observes a
	// half-started instance and a failed Start leaves the component cleanly
	// "not started".
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}

	if err := p.ensureDatabases(ctx); err != nil {
		_ = pg.Stop()
		return fmt.Errorf("ensure databases: %w", err)
	}

	p.mu.Lock()
	p.pg = pg
	p.mu.Unlock()
	return nil
}

// Stop the embedded Pg process. Idempotent — multiple calls return nil.
func (p *Postgres) Stop(_ context.Context) error {
	p.mu.Lock()
	pg := p.pg
	p.pg = nil
	p.mu.Unlock()
	if pg == nil {
		return nil
	}
	if err := pg.Stop(); err != nil {
		return fmt.Errorf("stop postgres: %w", err)
	}
	return nil
}

// Health returns Ready=true when the maintenance database accepts a ping.
func (p *Postgres) Health(ctx context.Context) HealthStatus {
	p.mu.Lock()
	pg := p.pg
	p.mu.Unlock()
	if pg == nil {
		return HealthStatus{Ready: false, Message: "not started"}
	}
	db, err := p.open(ctx, "postgres")
	if err != nil {
		return HealthStatus{Ready: false, Message: err.Error()}
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return HealthStatus{Ready: false, Message: err.Error()}
	}
	return HealthStatus{Ready: true, Message: fmt.Sprintf("listening on :%d", p.cfg.Port)}
}

// Port returns the effective listen port (after defaulting), for components
// that address this instance by port rather than DSN (Keycloak's JDBC URL).
func (p *Postgres) Port() uint32 { return p.cfg.Port }

// DSN returns a libpq connection string for a given database on this instance.
// Downstream components (Temporal, knowledge service, etc.) consume this.
func (p *Postgres) DSN(dbname string) string {
	return fmt.Sprintf("host=localhost port=%d user=reckon password=%s dbname=%s sslmode=%s",
		p.cfg.Port, p.cfg.Password, dbname, p.cfg.SSLMode)
}

func (p *Postgres) ensureDatabases(ctx context.Context) error {
	db, err := p.open(ctx, "postgres")
	if err != nil {
		return err
	}
	defer db.Close()

	for _, spec := range p.cfg.Databases {
		if err := ctx.Err(); err != nil {
			return err
		}
		var exists bool
		err := db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", spec.Name,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("query database %s: %w", spec.Name, err)
		}
		if exists {
			continue
		}
		log.Printf("postgres: creating database %s", spec.Name)
		// CREATE DATABASE doesn't accept parameterized identifiers; the name
		// comes from our config (not user input) so the formatted statement
		// is safe.
		stmt := fmt.Sprintf(`CREATE DATABASE %q`, spec.Name)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create database %s: %w", spec.Name, err)
		}
	}

	// Clean up legacy databases that no longer correspond to an active
	// component: aatu_temporal from installs that predate Temporal moving to
	// its own SQLite store, and aatu_* databases from pre-rename installs
	// (the project was previously named "aatu"). Idempotent: no-op when
	// the database is absent. Errors are non-fatal — drop failure shouldn't
	// block startup.
	for _, legacy := range []string{"aatu_temporal", "aatu_main", "aatu_knowledge"} {
		stmt := fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, legacy)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			log.Printf("postgres: could not drop legacy %s database (non-fatal): %v", legacy, err)
		}
	}

	// Apply migrations for each spec that supplied them. golang-migrate
	// tracks applied versions in schema_migrations inside each database;
	// re-running `reckon start` is idempotent.
	for _, spec := range p.cfg.Databases {
		if spec.Migrations == nil && len(spec.ExtraMigrations) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		log.Printf("postgres: applying migrations to %s", spec.Name)
		if spec.Migrations != nil {
			if err := pgmigrate.Run(p.DSN(spec.Name), spec.Migrations, spec.Name); err != nil {
				return fmt.Errorf("migrate %s: %w", spec.Name, err)
			}
		}
		for _, extra := range spec.ExtraMigrations {
			if err := pgmigrate.RunWithTable(p.DSN(spec.Name), extra.FS, spec.Name+":"+extra.Table, extra.Table); err != nil {
				return fmt.Errorf("migrate %s [%s]: %w", spec.Name, extra.Table, err)
			}
		}
	}
	return nil
}

func (p *Postgres) open(ctx context.Context, dbname string) (*sql.DB, error) {
	db, err := sql.Open("postgres", p.DSN(dbname))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// Brief retry loop in case Pg is still warming up immediately post-Start.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := db.PingContext(ctx); err == nil {
			return db, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			_ = db.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("postgres ping timeout on %s", dbname)
}
