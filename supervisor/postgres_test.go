package supervisor

import (
	"context"
	"path/filepath"
	"testing"
	"time"
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
		DataDir:   dir,
		Port:      0, // use default 5435
		Databases: []string{"aatu_main", "aatu_temporal", "aatu_knowledge"},
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
	for _, name := range []string{"aatu_main", "aatu_temporal", "aatu_knowledge"} {
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
		DataDir:   dir,
		Databases: []string{"aatu_main", "aatu_temporal", "aatu_knowledge"},
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
