package substrate

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"
)

// One embedded Postgres shared across the substrate tests (reckon-patterns:
// per-package TestMain with shared Pg). Port differs from other packages so
// parallel `go test ./...` doesn't collide. Migrations are applied by a local
// applier — the substrate never imports the host's migration tooling, and
// neither do its tests (§12 boundary).
var (
	testPg *embeddedpostgres.EmbeddedPostgres
	testDB *sql.DB
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "substrate-test-pg-*")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	cleanupDir := func() { _ = os.RemoveAll(dir) }

	testPg = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(15438).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		Username("test").Password("test").Database("substrate_test"))

	if err := testPg.Start(); err != nil {
		cleanupDir()
		log.Fatalf("embedded postgres start: %v", err)
	}
	stopPg := func() { _ = testPg.Stop() }

	dsn := "host=localhost port=15438 user=test password=test dbname=substrate_test sslmode=disable"
	testDB, err = sql.Open("postgres", dsn)
	if err != nil {
		stopPg()
		cleanupDir()
		log.Fatalf("open: %v", err)
	}
	if err := applyMigrations(testDB); err != nil {
		stopPg()
		cleanupDir()
		log.Fatalf("migrate: %v", err)
	}

	code := m.Run()
	_ = testDB.Close()
	stopPg()
	cleanupDir()
	os.Exit(code)
}

// applyMigrations runs the up migrations in filename order.
func applyMigrations(db *sql.DB) error {
	root := Migrations()
	var ups []string
	err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".up.sql") {
			return err
		}
		ups = append(ups, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(ups)
	for _, path := range ups {
		raw, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(raw)); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

// truncateAll resets state between tests sharing the DB.
func truncateAll(t *testing.T) {
	t.Helper()
	_, err := testDB.Exec(`TRUNCATE substrate_entries, substrate_embeddings, substrate_tombstones`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// testCorpora declares one corpus per shape under test.
func testCorpora() []CorpusDef {
	return []CorpusDef{
		{Name: "procedures", Archetype: Curated, Governance: Lightweight},
		{Name: "policies", Archetype: Curated, Governance: Gated},
		{Name: "case-summaries", Archetype: Derived},
	}
}

// fakeEmbedder returns fixed vectors per exact text, with a deterministic
// low-similarity default for anything unmapped.
type fakeEmbedder struct {
	byText map[string][]float32
	model  string
	calls  int
}

func (f *fakeEmbedder) Model() string {
	if f.model == "" {
		return "fake-embed-1"
	}
	return f.model
}

func (f *fakeEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	f.calls++
	out := make([][]float32, len(texts))
	for i, s := range texts {
		if v, ok := f.byText[s]; ok {
			out[i] = v
			continue
		}
		// Deterministic fallback orthogonal-ish to the mapped axes.
		out[i] = []float32{0, 0, 0, 1}
	}
	return out, nil
}

// newTestStore builds a store over the shared DB.
func newTestStore(t *testing.T, opts ...Option) *Postgres {
	t.Helper()
	if testing.Short() {
		t.Skip("substrate store tests need embedded postgres")
	}
	truncateAll(t)
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	tick := 0
	clock := func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}
	st, err := NewPostgres(testDB, testCorpora(), append([]Option{WithClock(clock)}, opts...)...)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	return st
}
