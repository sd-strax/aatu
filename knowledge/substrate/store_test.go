package substrate

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

const testNS = "tenant-1"

func TestPutLightweightPublishesOnWrite(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	e, err := st.Put(ctx, testNS, "procedures", Entry{
		Title:      "Ransomware triage",
		Body:       "Isolate first, then image.",
		Tags:       []string{"ransomware", "edr", "ransomware"},
		Meta:       map[string]any{"severity": "high"},
		Advice:     "isolate",
		AuthoredBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusPublished || e.PublishedAt == nil {
		t.Errorf("lightweight Put should publish on write: %+v", e.Status)
	}
	if e.Revision != 1 || e.ContentHash == "" || e.HashVersion != HashVersionV1 {
		t.Errorf("revision/hash not minted: rev=%d hash=%q v=%d", e.Revision, e.ContentHash, e.HashVersion)
	}
	if len(e.Tags) != 2 { // sorted + deduplicated
		t.Errorf("tags not canonicalized: %v", e.Tags)
	}

	got, err := st.Get(ctx, testNS, "procedures", e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != e.Title || got.Body != e.Body || got.Advice != "isolate" ||
		got.Meta["severity"] != "high" || got.AuthoredBy != "alice" || got.ContentHash != e.ContentHash {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestPutDerivedRequiresProvenance(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.Put(ctx, testNS, "case-summaries", Entry{Title: "T", Body: "B"}); err == nil {
		t.Fatal("derived Put without provenance.producer must fail")
	}
	e, err := st.Put(ctx, testNS, "case-summaries", Entry{
		Title:      "Concluded: lateral movement",
		Body:       "RDP pivot from WIN-FILE01.",
		Provenance: &Provenance{Producer: "case-summarizer", ProducerVersion: "1", GeneratorModel: "some-llm", SourceRef: "grouping--abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusPublished {
		t.Errorf("derived entries arrive PUBLISHED, got %s", e.Status)
	}
	got, _ := st.Get(ctx, testNS, "case-summaries", e.ID)
	if got.Provenance == nil || got.Provenance.SourceRef != "grouping--abc" {
		t.Errorf("provenance not persisted: %+v", got.Provenance)
	}
}

func TestGatedLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	e, err := st.Put(ctx, testNS, "policies", Entry{Title: "T3 approvals", Body: "Two-party for isolation."})
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusDraft || e.PublishedAt != nil {
		t.Fatalf("gated Put must land at DRAFT, got %s", e.Status)
	}

	// DRAFT → PUBLISHED directly is not a legal edge.
	err = st.Transition(ctx, testNS, "policies", e.ID, Transition{To: StatusPublished, Principals: []string{"sam"}})
	if !errors.Is(err, ErrBadTransition) {
		t.Fatalf("want ErrBadTransition, got %v", err)
	}

	if err := st.Transition(ctx, testNS, "policies", e.ID, Transition{To: StatusInReview}); err != nil {
		t.Fatal(err)
	}
	// Publish without a signer is refused; the signoff is recorded when given.
	err = st.Transition(ctx, testNS, "policies", e.ID, Transition{To: StatusPublished})
	if !errors.Is(err, ErrSignerRequired) {
		t.Fatalf("want ErrSignerRequired, got %v", err)
	}
	if err := st.Transition(ctx, testNS, "policies", e.ID, Transition{To: StatusPublished, Principals: []string{"sam"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(ctx, testNS, "policies", e.ID)
	if got.Status != StatusPublished || len(got.SignedOffBy) != 1 || got.SignedOffBy[0] != "sam" || got.PublishedAt == nil {
		t.Errorf("signoff not recorded: %+v", got)
	}

	if err := st.Transition(ctx, testNS, "policies", e.ID, Transition{To: StatusRetired}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.Get(ctx, testNS, "policies", e.ID)
	if got.Status != StatusRetired || got.RetiredAt == nil {
		t.Errorf("retire not applied: %+v", got)
	}
}

func TestReviseSupersedes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	r1, err := st.Put(ctx, testNS, "procedures", Entry{Title: "Phishing SOP", Body: "v1 body", Tags: []string{"phishing"}})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := st.Revise(ctx, testNS, "procedures", r1.ID, Revision{Title: "Phishing SOP", Body: "v2 body", Tags: []string{"phishing"}})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Revision != 2 || r2.Supersedes != r1.ID || r2.ID == r1.ID {
		t.Fatalf("revision chain wrong: %+v", r2)
	}
	if r2.ContentHash == r1.ContentHash {
		t.Error("content change must produce a new hash")
	}

	// The default List sees only the current revision.
	cur, err := st.List(ctx, testNS, "procedures", ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 1 || cur[0].ID != r2.ID {
		t.Errorf("List should return the current revision only: %+v", cur)
	}
	all, _ := st.List(ctx, testNS, "procedures", ListFilter{IncludeSuperseded: true})
	if len(all) != 2 {
		t.Errorf("IncludeSuperseded should surface the lineage: %d rows", len(all))
	}

	// Revising the superseded row again forks history — refused.
	if _, err := st.Revise(ctx, testNS, "procedures", r1.ID, Revision{Title: "x", Body: "y"}); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("want ErrSuperseded, got %v", err)
	}

	// The prior revision's content stays hash-addressable (§6).
	snap, err := st.Snapshot(ctx, testNS, r1.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Purged || snap.Content.Body != "v1 body" {
		t.Errorf("superseded content not attestable: %+v", snap)
	}
}

func TestPurgeLeavesTombstone(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	e, err := st.Put(ctx, testNS, "procedures", Entry{Title: "To purge", Body: "Sensitive."})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Purge(ctx, testNS, "procedures", e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, testNS, "procedures", e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged entry still readable: %v", err)
	}
	snap, err := st.Snapshot(ctx, testNS, e.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Purged || snap.PurgedAt == nil || snap.Content.Body != "" {
		t.Errorf("purge must answer with a tombstone, not content: %+v", snap)
	}
}

func TestSnapshotUnknownHash(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Snapshot(context.Background(), testNS, "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestNamespaceIsolation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	e, err := st.Put(ctx, "tenant-a", "procedures", Entry{Title: "A only", Body: "B"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "tenant-b", "procedures", e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace read must not resolve: %v", err)
	}
	if _, err := st.Snapshot(ctx, "tenant-b", e.ContentHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace snapshot must not resolve: %v", err)
	}
}

func TestUnknownCorpusAndBadNamespace(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if _, err := st.Put(ctx, testNS, "nope", Entry{Title: "T", Body: "B"}); !errors.Is(err, ErrUnknownCorpus) {
		t.Fatalf("want ErrUnknownCorpus, got %v", err)
	}
	if _, err := st.Get(ctx, "", "procedures", uuid.New()); err == nil {
		t.Fatal("empty namespace must be rejected")
	}
}

func TestWriteTimeEmbeddingAndReindex(t *testing.T) {
	fake := &fakeEmbedder{}
	st := newTestStore(t, WithEmbedder(fake))
	ctx := context.Background()

	e, err := st.Put(ctx, testNS, "procedures", Entry{Title: "T", Body: "B"})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM substrate_embeddings WHERE entry_id = $1 AND model = 'fake-embed-1'`, e.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Put did not embed: %d rows", n)
	}

	// A model switch leaves rows unembedded under the new model; Reindex is
	// the §10 migration path.
	st2, err := NewPostgres(testDB, testCorpora(), WithEmbedder(&fakeEmbedder{model: "new-model"}))
	if err != nil {
		t.Fatal(err)
	}
	count, err := st2.Reindex(ctx, testNS)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("Reindex embedded %d, want 1", count)
	}
	if count, err = st2.Reindex(ctx, testNS); err != nil || count != 0 {
		t.Fatalf("second Reindex should be a no-op: %d, %v", count, err)
	}
}
