package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sd-strax/reckon/internal/pgmigrate"
)

// testPg is a single embedded-postgres shared across the knowledge tests; it
// runs the reckon_knowledge migrations. Port differs from other packages' test
// Pg so parallel `go test ./...` processes don't collide.
var (
	testPg    *embeddedpostgres.EmbeddedPostgres
	testDB    *sql.DB
	testReady bool
)

var testTenant = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "knowledge-test-pg-*")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	cleanupDir := func() { _ = os.RemoveAll(dir) }

	testPg = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(15437).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		Username("test").Password("test").Database("reckon_knowledge"))

	if err := testPg.Start(); err != nil {
		cleanupDir()
		log.Fatalf("embedded postgres start: %v", err)
	}
	dsn := "host=localhost port=15437 user=test password=test dbname=reckon_knowledge sslmode=disable"
	if err := pgmigrate.Run(dsn, Migrations(), "reckon_knowledge"); err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("migrate: %v", err)
	}
	testDB, err = sql.Open("postgres", dsn)
	if err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("sql.Open: %v", err)
	}

	testReady = true
	code := m.Run()
	_ = testDB.Close()
	_ = testPg.Stop()
	cleanupDir()
	os.Exit(code)
}

func reset(t *testing.T) *Store {
	t.Helper()
	if !testReady {
		t.Skip("embedded postgres not available")
	}
	if _, err := testDB.Exec(`TRUNCATE sops`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return NewStore(testDB)
}

// TestSOP_CRUD walks create → get → list → update → retire and the retired
// visibility rules.
func TestSOP_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	s := reset(t)
	ctx := context.Background()

	id, err := s.Create(ctx, SOP{
		TenantID: testTenant, Title: "Ransomware containment",
		Body: "Isolate first, preserve volatile evidence, notify the on-call lead.",
		Tags: []string{"ransomware", "T1486"}, Recommendation: "isolate",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.Get(ctx, testTenant, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusPublished || got.Recommendation != "isolate" || got.PublishedAt == nil {
		t.Errorf("created SOP: status=%q rec=%q published=%v; want published/isolate/set", got.Status, got.Recommendation, got.PublishedAt)
	}
	if len(got.Tags) != 2 {
		t.Errorf("tags = %v; want 2", got.Tags)
	}

	if err := s.Update(ctx, testTenant, id, "Ransomware containment", "Updated body.", []string{"ransomware"}, "require-secondary"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.Get(ctx, testTenant, id)
	if got.Body != "Updated body." || got.Recommendation != "require-secondary" {
		t.Errorf("update not applied: %+v", got)
	}

	// List excludes retired.
	if err := s.Retire(ctx, testTenant, id); err != nil {
		t.Fatalf("retire: %v", err)
	}
	list, _ := s.List(ctx, testTenant, false)
	if len(list) != 0 {
		t.Errorf("retired SOP visible in default list: %d", len(list))
	}
	list, _ = s.List(ctx, testTenant, true)
	if len(list) != 1 || list[0].Status != StatusRetired {
		t.Errorf("include-retired list wrong: %+v", list)
	}

	// A retired SOP can't be updated.
	if err := s.Update(ctx, testTenant, id, "x", "y", nil, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of retired SOP: err=%v; want ErrNotFound", err)
	}
}

// TestRecallSOPs covers keyword ranking, the tag hard-filter, retired exclusion,
// and EMPTY coverage.
func TestRecallSOPs(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	s := reset(t)
	ctx := context.Background()

	mk := func(title, body string, tags ...string) uuid.UUID {
		id, err := s.Create(ctx, SOP{TenantID: testTenant, Title: title, Body: body, Tags: tags})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	ransom := mk("Ransomware playbook", "On ransomware detection, isolate the host immediately and preserve shadow copies.", "ransomware", "T1486")
	mk("Phishing triage", "For phishing reports, quarantine the message and check click telemetry.", "phishing", "T1566")
	mk("BEC response", "Business email compromise: reset the mailbox and review inbox rules.", "bec")

	// Empty-query, no filter → recency (all non-retired).
	all, err := s.RecallSOPs(ctx, testTenant, RecallRequest{})
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if all.Coverage != CoverageComplete || len(all.Results) != 3 {
		t.Errorf("recall-all: coverage=%q n=%d; want COMPLETE/3", all.Coverage, len(all.Results))
	}

	// Full-text query → ransomware SOP ranks top.
	q, _ := s.RecallSOPs(ctx, testTenant, RecallRequest{Query: "ransomware isolate host"})
	if len(q.Results) == 0 || q.Results[0].SOPID != ransom {
		t.Errorf("query did not rank the ransomware SOP first: %+v", q.Results)
	}
	if q.Results[0].Score <= 0 {
		t.Errorf("full-text score = %v; want > 0", q.Results[0].Score)
	}

	// Tag hard-filter.
	tagged, _ := s.RecallSOPs(ctx, testTenant, RecallRequest{Tags: []string{"phishing"}})
	if len(tagged.Results) != 1 || tagged.Results[0].Title != "Phishing triage" {
		t.Errorf("tag filter wrong: %+v", tagged.Results)
	}

	// No match → EMPTY (evidence-of-absence).
	none, _ := s.RecallSOPs(ctx, testTenant, RecallRequest{Query: "cryptomining kubernetes"})
	if none.Coverage != CoverageEmpty || len(none.Results) != 0 {
		t.Errorf("no-match: coverage=%q n=%d; want EMPTY/0", none.Coverage, len(none.Results))
	}

	// Retired excluded by default.
	if err := s.Retire(ctx, testTenant, ransom); err != nil {
		t.Fatal(err)
	}
	after, _ := s.RecallSOPs(ctx, testTenant, RecallRequest{Query: "ransomware"})
	if len(after.Results) != 0 {
		t.Errorf("retired SOP returned by default recall: %+v", after.Results)
	}
}
