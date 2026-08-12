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
	"github.com/sd-strax/reckon/knowledge/substrate"
)

// testPg is a single embedded-postgres shared across the knowledge tests. It
// runs both migration sets on reckon_knowledge exactly as runtime does — the
// host's knowledge migrations under the default table and the substrate's
// under its own — so the two independently-versioned schemas coexist. Port
// differs from other packages' test Pg so parallel `go test ./...` doesn't
// collide.
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
		log.Fatalf("knowledge migrate: %v", err)
	}
	if err := pgmigrate.RunWithTable(dsn, substrate.Migrations(), "reckon_knowledge_substrate", "substrate_schema_migrations"); err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("substrate migrate: %v", err)
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

// reset truncates the substrate tables and returns a fresh facade store over a
// keyword-only substrate (no embedder) unless opts add one.
func reset(t *testing.T, opts ...substrate.Option) *Store {
	t.Helper()
	if !testReady {
		t.Skip("embedded postgres not available")
	}
	if _, err := testDB.Exec(`TRUNCATE substrate_entries, substrate_embeddings, substrate_tombstones`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	sub, err := substrate.NewPostgres(testDB, []substrate.CorpusDef{
		{Name: CorpusProcedures, Archetype: substrate.Curated, Governance: substrate.Lightweight},
		{Name: CorpusCaseSummaries, Archetype: substrate.Derived},
	}, opts...)
	if err != nil {
		t.Fatalf("substrate: %v", err)
	}
	return NewStore(sub)
}

// TestSOP_CRUD walks create → get → list → update → retire and the retired
// visibility rules. Update goes through a substrate revision under the hood,
// but the SOP's lineage id must stay stable across it.
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
		AuthorID: "11111111-1111-1111-1111-111111111111",
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
	// The reserved lineage tag must never leak into the user-facing tags.
	if len(got.Tags) != 2 {
		t.Errorf("tags = %v; want 2 (no reserved lineage tag)", got.Tags)
	}
	for _, tag := range got.Tags {
		if len(tag) >= 2 && tag[:2] == "__" {
			t.Errorf("reserved tag leaked to the SOP view: %q", tag)
		}
	}

	if err := s.Update(ctx, testTenant, id, "Ransomware containment", "Updated body.", []string{"ransomware"}, "require-secondary"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.Get(ctx, testTenant, id) // SAME id after a revision
	if got.ID != id {
		t.Errorf("lineage id moved on update: %s -> %s", id, got.ID)
	}
	if got.Body != "Updated body." || got.Recommendation != "require-secondary" || len(got.Tags) != 1 {
		t.Errorf("update not applied: %+v", got)
	}

	// Exactly one current SOP after an edit — the prior revision is superseded,
	// not a second list entry.
	list, _ := s.List(ctx, testTenant, false)
	if len(list) != 1 {
		t.Errorf("edit produced a duplicate list entry: %d", len(list))
	}

	// List excludes retired.
	if err := s.Retire(ctx, testTenant, id); err != nil {
		t.Fatalf("retire: %v", err)
	}
	list, _ = s.List(ctx, testTenant, false)
	if len(list) != 0 {
		t.Errorf("retired SOP visible in default list: %d", len(list))
	}
	list, _ = s.List(ctx, testTenant, true)
	if len(list) != 1 || list[0].Status != StatusRetired || list[0].ID != id {
		t.Errorf("include-retired list wrong: %+v", list)
	}

	// A retired SOP can't be updated.
	if err := s.Update(ctx, testTenant, id, "x", "y", nil, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of retired SOP: err=%v; want ErrNotFound", err)
	}
}

func TestGetUnknownSOP(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	s := reset(t)
	if _, err := s.Get(context.Background(), testTenant, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("get unknown: err=%v; want ErrNotFound", err)
	}
}

// TestRecallSOPs covers keyword ranking (the degraded backend), the tag
// hard-filter, empty-query browse, retired exclusion, and EMPTY coverage.
func TestRecallSOPs(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	s := reset(t) // keyword backend (no embedder)
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

	// Empty-query, no filter → recency browse (all non-retired).
	all, err := s.RecallSOPs(ctx, testTenant, RecallRequest{})
	if err != nil {
		t.Fatalf("recall: %v", err)
	}
	if all.Coverage != CoverageComplete || len(all.Results) != 3 {
		t.Errorf("recall-all: coverage=%q n=%d; want COMPLETE/3", all.Coverage, len(all.Results))
	}

	// Keyword query → ransomware SOP ranks top, attributed to the fallback.
	q, _ := s.RecallSOPs(ctx, testTenant, RecallRequest{Query: "ransomware isolate host"})
	if len(q.Results) == 0 || q.Results[0].SOPID != ransom {
		t.Errorf("query did not rank the ransomware SOP first: %+v", q.Results)
	}
	if q.Results[0].Score <= 0 {
		t.Errorf("keyword score = %v; want > 0", q.Results[0].Score)
	}
	if q.Results[0].Backend != "pg-fts/1" {
		t.Errorf("backend attribution = %q; want pg-fts/1", q.Results[0].Backend)
	}
	// Reserved lineage tag must not surface in match results.
	for _, tag := range q.Results[0].Tags {
		if len(tag) >= 2 && tag[:2] == "__" {
			t.Errorf("reserved tag leaked into a recall result: %q", tag)
		}
	}

	// Tag hard-filter via empty-query browse.
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

// TestRecallSemantic proves the facade drives the vector backend and resolves
// SOP ids from the lineage tag on a recall hit (which carries no meta).
func TestRecallSemantic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	emb := &stubEmbedder{vec: map[string][]float32{}}
	s := reset(t, substrate.WithEmbedder(emb))
	ctx := context.Background()

	// Two SOPs on orthogonal axes; the query aligns with the first.
	emb.set("Ransomware isolation\n\nIsolate the host, preserve memory.", 1, 0)
	emb.set("Phishing triage\n\nCheck headers, detonate attachments.", 0, 1)
	emb.set("what do we do when a machine is ransomed?", 1, 0)

	rid, err := s.Create(ctx, SOP{TenantID: testTenant, Title: "Ransomware isolation", Body: "Isolate the host, preserve memory.", Tags: []string{"ransomware"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, SOP{TenantID: testTenant, Title: "Phishing triage", Body: "Check headers, detonate attachments.", Tags: []string{"phishing"}}); err != nil {
		t.Fatal(err)
	}

	res, err := s.RecallSOPs(ctx, testTenant, RecallRequest{Query: "what do we do when a machine is ransomed?"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) == 0 || res.Results[0].SOPID != rid {
		t.Fatalf("semantic recall did not rank/resolve the ransomware SOP: %+v", res.Results)
	}
	if res.Results[0].Backend != "vector-cosine/1/stub-embed" {
		t.Errorf("backend = %q; want vector-cosine/1/stub-embed", res.Results[0].Backend)
	}
}

// stubEmbedder returns fixed 2-D vectors per exact text; unmapped text is
// orthogonal to both axes so it never falsely matches.
type stubEmbedder struct{ vec map[string][]float32 }

func (e *stubEmbedder) Model() string { return "stub-embed" }
func (e *stubEmbedder) set(text string, x, y float32) {
	e.vec[text] = []float32{x, y}
}
func (e *stubEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, s := range texts {
		if v, ok := e.vec[s]; ok {
			out[i] = v
		} else {
			out[i] = []float32{0, 0.0001} // near-zero, effectively orthogonal
		}
	}
	return out, nil
}
