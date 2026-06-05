package supervisor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sd-strax/aatu/aggregate"
	"github.com/sd-strax/aatu/knowledge"
)

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
	pg := NewPostgres(PostgresConfig{
		DataDir: dir,
		Port:    0, // use default 5435
		Databases: []DatabaseSpec{
			{Name: "aatu_main"},
			{Name: "aatu_knowledge"},
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
	for _, name := range []string{"aatu_main", "aatu_knowledge"} {
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

	// Write to aatu_main; verify it persists across restart
	main, err := pg.open(ctx, "aatu_main")
	if err != nil {
		t.Fatalf("open aatu_main: %v", err)
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
		DataDir: dir,
		Databases: []DatabaseSpec{
			{Name: "aatu_main"},
			{Name: "aatu_knowledge"},
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

	main2, err := pg2.open(ctx, "aatu_main")
	if err != nil {
		t.Fatalf("open aatu_main after restart: %v", err)
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
	pg := NewPostgres(PostgresConfig{
		DataDir: dir,
		Port:    0,
		Databases: []DatabaseSpec{
			{Name: "aatu_main", Migrations: aggregate.Migrations()},
			{Name: "aatu_knowledge", Migrations: knowledge.Migrations()},
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

	// aatu_main: events, stix_objects, stix_relationships, ai_tool_calls, ai_transcripts
	mainDB, err := pg.open(ctx, "aatu_main")
	if err != nil {
		t.Fatalf("open aatu_main: %v", err)
	}
	defer mainDB.Close()

	for _, table := range []string{"events", "stix_objects", "stix_relationships", "ai_tool_calls", "ai_transcripts"} {
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
			t.Errorf("aatu_main: table %s was not created by aggregate migrations", table)
		}
	}

	// aatu_knowledge: sops, investigation_summaries
	knowDB, err := pg.open(ctx, "aatu_knowledge")
	if err != nil {
		t.Fatalf("open aatu_knowledge: %v", err)
	}
	defer knowDB.Close()

	for _, table := range []string{"sops", "investigation_summaries"} {
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
			t.Errorf("aatu_knowledge: table %s was not created by knowledge migrations", table)
		}
	}

	// Verify schema_migrations records the right version in each database.
	var mainVersion int
	if err := mainDB.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&mainVersion); err != nil {
		t.Errorf("aatu_main schema_migrations: %v", err)
	}
	if mainVersion != 3 {
		t.Errorf("aatu_main version = %d; want 3 (three aggregate migrations)", mainVersion)
	}

	var knowVersion int
	if err := knowDB.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&knowVersion); err != nil {
		t.Errorf("aatu_knowledge schema_migrations: %v", err)
	}
	if knowVersion != 2 {
		t.Errorf("aatu_knowledge version = %d; want 2 (two knowledge migrations)", knowVersion)
	}

	// Restart against the same data dir; migrations should be a no-op.
	if err := pg.Stop(ctx); err != nil {
		t.Errorf("stop: %v", err)
	}

	pg2 := NewPostgres(PostgresConfig{
		DataDir: dir,
		Databases: []DatabaseSpec{
			{Name: "aatu_main", Migrations: aggregate.Migrations()},
			{Name: "aatu_knowledge", Migrations: knowledge.Migrations()},
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
	mainDB2, err := pg2.open(ctx, "aatu_main")
	if err != nil {
		t.Fatalf("open aatu_main after restart: %v", err)
	}
	defer mainDB2.Close()
	var mainVersion2 int
	if err := mainDB2.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations",
	).Scan(&mainVersion2); err != nil {
		t.Errorf("aatu_main schema_migrations after restart: %v", err)
	}
	if mainVersion2 != mainVersion {
		t.Errorf("version changed after restart: was %d, now %d", mainVersion, mainVersion2)
	}
}
