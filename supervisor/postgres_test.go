package supervisor

import (
	"context"
	"io/fs"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/knowledge/substrate"
)

// freePort asks the kernel for an unused TCP port. The lifecycle tests must
// not assume the default 5435 is free — a running local reckon stack owns it,
// and `make test-all` should coexist with the stack, not require stopping it.
// (The tiny close-to-bind race is acceptable in tests.)
func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port) //nolint:gosec // ports fit uint32
}

// countUpMigrations returns the number of up-migrations in a migration FS.
// golang-migrate records the highest applied version in schema_migrations,
// which for sequential 0001..NNNN migrations equals the up-migration count.
// Deriving the expectation here keeps the version assertions from drifting
// every time a migration is added (which is what broke this test at 0004).
func countUpMigrations(t *testing.T, mfs fs.FS) int {
	t.Helper()
	ups, err := fs.Glob(mfs, "*.up.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	return len(ups)
}

// TestPostgresLifecycle exercises the full Postgres component lifecycle:
// start, database creation, health, persistence across restart, stop.
//
// First-run cost: ~10–15s for embedded-postgres to download the Pg binary.
// Subsequent runs reuse the cached binary (~2–3s warm).
//
// Skipped in short mode.
func TestPostgresLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Postgres lifecycle test in short mode")
	}

	dir := filepath.Join(t.TempDir(), "pg")
	port := freePort(t) // never assume 5435 is free (a live local stack owns it)
	pg := NewPostgres(PostgresConfig{
		DataDir:  dir,
		Password: "test-pw",
		Port:     port,
		Databases: []DatabaseSpec{
			{Name: "reckon_main"},
			{Name: "reckon_knowledge"},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := pg.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Health check after start
	h := pg.Health(ctx)
	if !h.Ready {
		t.Errorf("expected ready; got %+v", h)
	}

	// All three databases should now exist
	db, err := pg.open(ctx, "postgres")
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	for _, name := range []string{"reckon_main", "reckon_knowledge"} {
		var exists bool
		err := db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", name,
		).Scan(&exists)
		if err != nil {
			t.Errorf("query %s: %v", name, err)
		}
		if !exists {
			t.Errorf("database %s was not created", name)
		}
	}
	db.Close()

	// Write to reckon_main; verify it persists across restart
	main, err := pg.open(ctx, "reckon_main")
	if err != nil {
		t.Fatalf("open reckon_main: %v", err)
	}
	if _, err := main.ExecContext(ctx,
		"CREATE TABLE IF NOT EXISTS test_persist (id INT PRIMARY KEY, val TEXT)",
	); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := main.ExecContext(ctx,
		"INSERT INTO test_persist VALUES (1, 'hello') ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val",
	); err != nil {
		t.Fatalf("insert: %v", err)
	}
	main.Close()

	if err := pg.Stop(ctx); err != nil {
		t.Errorf("stop: %v", err)
	}

	// Restart against the same data directory; existing data should be visible
	pg2 := NewPostgres(PostgresConfig{
		DataDir:  dir,
		Password: "test-pw",
		Port:     port, // same port as the first boot, never the 5435 default
		Databases: []DatabaseSpec{
			{Name: "reckon_main"},
			{Name: "reckon_knowledge"},
		},
	})
	if err := pg2.Start(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = pg2.Stop(stopCtx)
	})

	main2, err := pg2.open(ctx, "reckon_main")
	if err != nil {
		t.Fatalf("open reckon_main after restart: %v", err)
	}
	defer main2.Close()
	var val string
	if err := main2.QueryRowContext(ctx,
		"SELECT val FROM test_persist WHERE id=1",
	).Scan(&val); err != nil {
		t.Fatalf("query persisted row: %v", err)
	}
	if val != "hello" {
		t.Errorf("persisted value = %q; want %q", val, "hello")
	}
}

// TestPostgresMigrations applies the real aggregate + knowledge migrations
// and verifies the expected tables exist + idempotent re-application.
// Same slow-test caveat as TestPostgresLifecycle: skipped under -short,
// shares the embedded-postgres binary cache.
func TestPostgresMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Postgres migrations test in short mode")
	}

	dir := filepath.Join(t.TempDir(), "pg")
	port := freePort(t)
	pg := NewPostgres(PostgresConfig{
		DataDir:  dir,
		Password: "test-pw",
		Port:     port,
		Databases: []DatabaseSpec{
			{Name: "reckon_main", Migrations: aggregate.Migrations()},
			{
				Name:       "reckon_knowledge",
				Migrations: knowledge.Migrations(),
				ExtraMigrations: []ExtraMigrationSet{
					{FS: substrate.Migrations(), Table: "substrate_schema_migrations"},
				},
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := pg.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_ = pg.Stop(stopCtx)
	})

	// reckon_main: tenants, events, stix_objects, stix_edges, ai_tool_calls, ai_transcripts, investigation_current
	mainDB, err := pg.open(ctx, "reckon_main")
	if err != nil {
		t.Fatalf("open reckon_main: %v", err)
	}
	defer mainDB.Close()

	for _, table := range []string{"tenants", "events", "stix_objects", "stix_edges", "ai_tool_calls", "ai_transcripts", "investigation_current"} {
		var exists bool
		err := mainDB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table,
		).Scan(&exists)
		if err != nil {
			t.Errorf("query table %s: %v", table, err)
			continue
		}
		if !exists {
			t.Errorf("reckon_main: table %s was not created by aggregate migrations", table)
		}
	}

	// reckon_knowledge: sops, investigation_summaries
	knowDB, err := pg.open(ctx, "reckon_knowledge")
	if err != nil {
		t.Fatalf("open reckon_knowledge: %v", err)
	}
	defer knowDB.Close()

	// reckon_knowledge carries BOTH migration sets: the host's knowledge tables
	// and the substrate's own, each under its own tracking table.
	for _, table := range []string{"sops", "investigation_summaries", "substrate_entries", "substrate_embeddings", "substrate_schema_migrations"} {
		var exists bool
		err := knowDB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table,
		).Scan(&exists)
		if err != nil {
			t.Errorf("query table %s: %v", table, err)
			continue
		}
		if !exists {
			t.Errorf("reckon_knowledge: table %s was not created", table)
		}
	}

	// The two sets version independently — the substrate's tracking table
	// records its own version, unaffected by the host set on schema_migrations.
	var subVersion int
	if err := knowDB.QueryRowContext(ctx,
		"SELECT version FROM substrate_schema_migrations",
	).Scan(&subVersion); err != nil {
		t.Errorf("substrate_schema_migrations: %v", err)
	}
	if want := countUpMigrations(t, substrate.Migrations()); subVersion != want {
		t.Errorf("substrate version = %d; want %d (substrate up-migrations)", subVersion, want)
	}

	// Verify schema_migrations records the right version in each database.
	var mainVersion int
	if err := mainDB.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&mainVersion); err != nil {
		t.Errorf("reckon_main schema_migrations: %v", err)
	}
	if want := countUpMigrations(t, aggregate.Migrations()); mainVersion != want {
		t.Errorf("reckon_main version = %d; want %d (aggregate up-migrations)", mainVersion, want)
	}

	var knowVersion int
	if err := knowDB.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&knowVersion); err != nil {
		t.Errorf("reckon_knowledge schema_migrations: %v", err)
	}
	if want := countUpMigrations(t, knowledge.Migrations()); knowVersion != want {
		t.Errorf("reckon_knowledge version = %d; want %d (knowledge up-migrations)", knowVersion, want)
	}

	// Restart against the same data dir; migrations should be a no-op.
	if err := pg.Stop(ctx); err != nil {
		t.Errorf("stop: %v", err)
	}

	pg2 := NewPostgres(PostgresConfig{
		DataDir:  dir,
		Password: "test-pw",
		Port:     port, // same port as the first boot, never the 5435 default
		Databases: []DatabaseSpec{
			{Name: "reckon_main", Migrations: aggregate.Migrations()},
			{
				Name:       "reckon_knowledge",
				Migrations: knowledge.Migrations(),
				ExtraMigrations: []ExtraMigrationSet{
					{FS: substrate.Migrations(), Table: "substrate_schema_migrations"},
				},
			},
		},
	})
	if err := pg2.Start(ctx); err != nil {
		t.Fatalf("restart with same dir: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_ = pg2.Stop(stopCtx)
	})

	// Schema versions unchanged
	mainDB2, err := pg2.open(ctx, "reckon_main")
	if err != nil {
		t.Fatalf("open reckon_main after restart: %v", err)
	}
	defer mainDB2.Close()
	var mainVersion2 int
	if err := mainDB2.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&mainVersion2); err != nil {
		t.Errorf("reckon_main schema_migrations after restart: %v", err)
	}
	if mainVersion2 != mainVersion {
		t.Errorf("version changed after restart: was %d, now %d", mainVersion, mainVersion2)
	}
}
