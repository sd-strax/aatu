package aggregate

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sd-strax/reckon/internal/pgmigrate"
)

// testPg is a single embedded-postgres instance shared across all aggregate
// integration tests in this package (set up by TestMain, torn down on exit).
// Each test gets a fresh schema by running TRUNCATE on the event store +
// projection tables in cleanup.
var (
	testPg    *embeddedpostgres.EmbeddedPostgres
	testDB    *sql.DB
	testReady bool
)

func TestMain(m *testing.M) {
	// Without an explicit flag.Parse here, testing.Short() panics ("called
	// before Parse"). m.Run does this for us but TestMain runs first.
	flag.Parse()
	if testing.Short() {
		// Tests will skip themselves; no need to spin up Pg.
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "aggregate-test-pg-*")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	// Use a named cleanup function we can call before any os.Exit path.
	// `defer` here is unsafe because log.Fatalf calls os.Exit which skips
	// deferred functions — same reason the gocritic linter flags this.
	cleanupDir := func() { _ = os.RemoveAll(dir) }

	testPg = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(15436).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		Username("test").
		Password("test").
		Database("reckon_test"))

	if err := testPg.Start(); err != nil {
		cleanupDir()
		log.Fatalf("embedded postgres start: %v", err)
	}

	dsn := "host=localhost port=15436 user=test password=test dbname=reckon_test sslmode=disable"
	if err := pgmigrate.Run(dsn, Migrations(), "reckon_main"); err != nil {
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

// resetTables wipes events + projection tables so each test starts clean.
// Caller is responsible for setup/teardown ordering.
func resetTables(t *testing.T) {
	t.Helper()
	if !testReady {
		t.Skip("embedded postgres not available")
	}
	_, err := testDB.Exec(`TRUNCATE events, investigation_current, action_current, hypothesis_current, prediction_current, stix_objects, evidence_pin_current, ref_appearances`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func newTestHandler() *Handler {
	return NewHandler(NewStore(testDB), InvestigationCurrentProjector{}, ActionCurrentProjector{}, ReasoningNodeProjector{}, VerdictPinProjector{}, RefAppearanceProjector{})
}

// testTenantID is the tenant stamped on envelopes built by the aggregate
// tests. Any non-zero UUID exercises the tenant-aware write path identically.
var testTenantID = uuid.New()

func newTestEnvelope(actorID string) Envelope {
	return Envelope{
		AggregateID:   uuid.New(),
		TenantID:      testTenantID,
		CorrelationID: uuid.New(),
		Actor:         Actor{PrincipalID: actorID},
		OccurredAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
}

// TestHandleCreateInvestigation is the A.4 done-bar: a handcrafted
// CreateInvestigation command persists an event, the projection updates,
// the projection is queryable.
func TestHandleCreateInvestigation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping aggregate integration test in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()

	env := newTestEnvelope("alice")
	cmd := CreateInvestigation{Title: "PHISH-2026-0042"}

	res, err := h.Handle(ctx, env, cmd)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.NewSequenceNo != 1 {
		t.Errorf("NewSequenceNo = %d; want 1", res.NewSequenceNo)
	}
	if len(res.AppliedEvents) != 1 {
		t.Fatalf("AppliedEvents len = %d; want 1", len(res.AppliedEvents))
	}
	if res.AppliedEvents[0].Type != EventTypeCreated {
		t.Errorf("event type = %q; want %q", res.AppliedEvents[0].Type, EventTypeCreated)
	}

	// Projection is queryable
	ic, err := LoadInvestigationCurrent(ctx, h.DB(), env.AggregateID)
	if err != nil {
		t.Fatalf("LoadInvestigationCurrent: %v", err)
	}
	if ic.Title != "PHISH-2026-0042" {
		t.Errorf("projection Title = %q; want %q", ic.Title, "PHISH-2026-0042")
	}
	if ic.Status != StatusDraft {
		t.Errorf("projection Status = %q; want %q", ic.Status, StatusDraft)
	}
	if ic.LastEventSequence != 1 {
		t.Errorf("LastEventSequence = %d; want 1", ic.LastEventSequence)
	}
}

// TestStaleSequenceRejected verifies the A.4 done-bar: a second command on
// the same aggregate at a stale sequence_no is rejected.
//
// CreateInvestigation specifically rejects "already exists" up front via
// applyCommand's existence check (state.Exists). The store-level concurrency
// check is exercised by the unit test below (TestStoreConcurrentInsert).
func TestStaleSequenceRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping aggregate integration test in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()

	env := newTestEnvelope("alice")

	if _, err := h.Handle(ctx, env, CreateInvestigation{Title: "first"}); err != nil {
		t.Fatalf("first Handle: %v", err)
	}

	// Second CreateInvestigation on the same aggregate should fail
	// (CreateInvestigation is only valid on a fresh aggregate).
	_, err := h.Handle(ctx, env, CreateInvestigation{Title: "second"})
	if err == nil {
		t.Fatal("expected error for second CreateInvestigation on same aggregate; got nil")
	}
}

// TestStoreConcurrentInsert verifies the store-level optimistic concurrency
// guard: two concurrent inserts at the same (aggregate_id, sequence_no)
// produce exactly one success and one ErrConcurrent.
func TestStoreConcurrentInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping aggregate integration test in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	s := NewStore(testDB)
	aggID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	actor := Actor{PrincipalID: "alice"}

	evt1 := Event{
		AggregateID: aggID, SequenceNo: 1, TenantID: testTenantID, Type: "test.event",
		Payload: []byte(`{"n":1}`),
		Actor:   actor, OccurredAt: now,
	}
	evt2 := Event{
		AggregateID: aggID, SequenceNo: 1, TenantID: testTenantID, Type: "test.event",
		Payload: []byte(`{"n":2}`),
		Actor:   actor, OccurredAt: now,
	}

	tx1, _ := testDB.BeginTx(ctx, nil)
	if err := s.AppendEventTx(ctx, tx1, evt1); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := tx1.Commit(); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	tx2, _ := testDB.BeginTx(ctx, nil)
	err := s.AppendEventTx(ctx, tx2, evt2)
	_ = tx2.Rollback()
	if !errors.Is(err, ErrConcurrent) {
		t.Errorf("second insert error = %v; want ErrConcurrent", err)
	}
}

// TestReplayFromCold verifies the A.4 done-bar: replay from cold produces
// identical projection state.
func TestReplayFromCold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping aggregate integration test in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()

	// Create three investigations
	envs := make([]Envelope, 3)
	titles := []string{"first", "second", "third"}
	for i := 0; i < 3; i++ {
		envs[i] = newTestEnvelope("alice")
		if _, err := h.Handle(ctx, envs[i], CreateInvestigation{Title: titles[i]}); err != nil {
			t.Fatalf("Handle %d: %v", i, err)
		}
	}

	// Snapshot the projection state
	beforeRows, err := testDB.QueryContext(ctx, `
		SELECT aggregate_id, title, status, last_event_sequence
		FROM investigation_current
		ORDER BY title
	`)
	if err != nil {
		t.Fatal(err)
	}
	type ICRow struct {
		AggID   AggregateID
		Title   string
		Status  string
		LastSeq int64
	}
	var before []ICRow
	for beforeRows.Next() {
		var r ICRow
		_ = beforeRows.Scan(&r.AggID, &r.Title, &r.Status, &r.LastSeq)
		before = append(before, r)
	}
	beforeRows.Close()

	if len(before) != 3 {
		t.Fatalf("pre-replay row count = %d; want 3", len(before))
	}

	// Cold replay
	if err := h.Replay(ctx); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	// Snapshot again
	afterRows, err := testDB.QueryContext(ctx, `
		SELECT aggregate_id, title, status, last_event_sequence
		FROM investigation_current
		ORDER BY title
	`)
	if err != nil {
		t.Fatal(err)
	}
	var after []ICRow
	for afterRows.Next() {
		var r ICRow
		_ = afterRows.Scan(&r.AggID, &r.Title, &r.Status, &r.LastSeq)
		after = append(after, r)
	}
	afterRows.Close()

	if len(after) != 3 {
		t.Fatalf("post-replay row count = %d; want 3", len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("row %d differs post-replay:\n  before: %+v\n  after:  %+v",
				i, before[i], after[i])
		}
	}
}

// TestLoadStream verifies events can be read back in sequence order.
func TestLoadStream(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping aggregate integration test in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()

	env := newTestEnvelope("alice")
	if _, err := h.Handle(ctx, env, CreateInvestigation{Title: "stream-test"}); err != nil {
		t.Fatal(err)
	}

	events, err := h.store.LoadStream(ctx, env.AggregateID)
	if err != nil {
		t.Fatalf("LoadStream: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d; want 1", len(events))
	}
	if events[0].Type != EventTypeCreated {
		t.Errorf("event type = %q; want %q", events[0].Type, EventTypeCreated)
	}
	if events[0].Actor.PrincipalID != "alice" {
		t.Errorf("actor.principal_id = %q; want alice", events[0].Actor.PrincipalID)
	}
}

// Pure unit-test on the applyCommand layer (no DB, no -short skip).
func TestApplyCommand_CreateInvestigationOnExistingAggregate(t *testing.T) {
	env := Envelope{
		AggregateID:   uuid.New(),
		TenantID:      testTenantID,
		CorrelationID: uuid.New(),
		Actor:         Actor{PrincipalID: "alice"},
		OccurredAt:    time.Now(),
	}
	existing := aggregateState{Seq: 5, Exists: true, Status: StatusActive}
	_, err := applyCommand(env, CreateInvestigation{Title: "x"}, existing)
	if err == nil {
		t.Fatal("expected error for CreateInvestigation on existing aggregate")
	}
}

func TestApplyCommand_ValidatesEnvelope(t *testing.T) {
	fresh := aggregateState{}

	// Missing principal
	_, err := applyCommand(Envelope{
		AggregateID:   uuid.New(),
		TenantID:      testTenantID,
		CorrelationID: uuid.New(),
		OccurredAt:    time.Now(),
	}, CreateInvestigation{Title: "x"}, fresh)
	if err == nil {
		t.Error("expected envelope validation failure for missing PrincipalID")
	}

	// Missing tenant
	_, err = applyCommand(Envelope{
		AggregateID:   uuid.New(),
		CorrelationID: uuid.New(),
		Actor:         Actor{PrincipalID: "alice"},
		OccurredAt:    time.Now(),
	}, CreateInvestigation{Title: "x"}, fresh)
	if err == nil {
		t.Error("expected envelope validation failure for missing TenantID")
	}

	// Missing correlation id
	_, err = applyCommand(Envelope{
		AggregateID: uuid.New(),
		TenantID:    testTenantID,
		Actor:       Actor{PrincipalID: "alice"},
		OccurredAt:  time.Now(),
	}, CreateInvestigation{Title: "x"}, fresh)
	if err == nil {
		t.Error("expected envelope validation failure for missing CorrelationID")
	}

	// Empty title
	_, err = applyCommand(Envelope{
		AggregateID:   uuid.New(),
		TenantID:      testTenantID,
		CorrelationID: uuid.New(),
		Actor:         Actor{PrincipalID: "alice"},
		OccurredAt:    time.Now(),
	}, CreateInvestigation{Title: ""}, fresh)
	if err == nil {
		t.Error("expected command validation failure for empty title")
	}
}
