package substrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Store is the substrate's Go contract (§7) — the source of truth; the wire
// contract (§8) is its projection. Consumed embedded (this implementation
// over a *sql.DB) or as a service.
type Store interface {
	// Write side.
	Put(ctx context.Context, ns, corpus string, e Entry) (Entry, error)
	Revise(ctx context.Context, ns, corpus string, id uuid.UUID, r Revision) (Entry, error)
	Transition(ctx context.Context, ns, corpus string, id uuid.UUID, t Transition) error
	Purge(ctx context.Context, ns, corpus string, id uuid.UUID) error

	// Read side.
	Get(ctx context.Context, ns, corpus string, id uuid.UUID) (Entry, error)
	List(ctx context.Context, ns, corpus string, f ListFilter) ([]Entry, error)
	Recall(ctx context.Context, ns string, q RecallQuery) (RecallResult, error)
	Snapshot(ctx context.Context, ns string, hash ContentHash) (Snapshot, error)
}

// Snapshot is the §6 attestation answer for a content hash: the full content
// object whose hash was ever served, or a purge tombstone ("content existed
// and was purged at T" — never pretending the hash was never served).
type Snapshot struct {
	Content     Content
	Hash        ContentHash
	HashVersion int
	Purged      bool
	PurgedAt    *time.Time
}

// Postgres is the reference Store implementation. Corpora are declared at
// construction (§2.2); the optional embedder selects the vector recall
// backend (§10) — without one, recall degrades to the keyword backend and
// says so in its ranker attribution.
type Postgres struct {
	db       *sql.DB
	corpora  map[string]CorpusDef
	embedder Embedder
	bands    BandCutoffs
	now      func() time.Time
}

// Option configures NewPostgres.
type Option func(*Postgres)

// WithEmbedder selects the vector recall backend and turns on write-time
// embedding. Writes then fail loudly when the embedder does — an entry the
// store cannot index is an error at write time, not a silent recall gap.
func WithEmbedder(e Embedder) Option { return func(p *Postgres) { p.embedder = e } }

// WithBands overrides the similarity-band cutoffs (§5.4) — calibration is
// part of a backend version's definition and may be tuned per deployment.
func WithBands(b BandCutoffs) Option { return func(p *Postgres) { p.bands = b } }

// WithClock injects time for tests.
func WithClock(now func() time.Time) Option { return func(p *Postgres) { p.now = now } }

// NewPostgres builds the store over an already-migrated database.
func NewPostgres(db *sql.DB, corpora []CorpusDef, opts ...Option) (*Postgres, error) {
	if len(corpora) == 0 {
		return nil, fmt.Errorf("substrate: at least one corpus must be declared")
	}
	byName := make(map[string]CorpusDef, len(corpora))
	for _, c := range corpora {
		if c.Name == "" {
			return nil, fmt.Errorf("substrate: corpus with empty name")
		}
		if c.Archetype != Curated && c.Archetype != Derived {
			return nil, fmt.Errorf("substrate: corpus %q: archetype must be CURATED or DERIVED", c.Name)
		}
		if _, dup := byName[c.Name]; dup {
			return nil, fmt.Errorf("substrate: corpus %q declared twice", c.Name)
		}
		if c.Archetype == Derived || c.Governance == "" {
			c.Governance = Lightweight // derived is implicitly lightweight (§2.2)
		}
		byName[c.Name] = c
	}
	p := &Postgres{db: db, corpora: byName, bands: DefaultBands, now: time.Now}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

func (p *Postgres) corpus(name string) (CorpusDef, error) {
	c, ok := p.corpora[name]
	if !ok {
		return CorpusDef{}, fmt.Errorf("%w: %q", ErrUnknownCorpus, name)
	}
	return c, nil
}

// Put stores a new entry (revision 1). Status lands per governance: curated
// LIGHTWEIGHT and derived publish on write; curated GATED lands at DRAFT.
func (p *Postgres) Put(ctx context.Context, ns, corpus string, e Entry) (Entry, error) {
	if err := validNamespace(ns); err != nil {
		return Entry{}, err
	}
	def, err := p.corpus(corpus)
	if err != nil {
		return Entry{}, err
	}
	if e.Title == "" || e.Body == "" {
		return Entry{}, fmt.Errorf("substrate: entry needs title and body")
	}
	if def.Archetype == Derived && (e.Provenance == nil || e.Provenance.Producer == "") {
		return Entry{}, fmt.Errorf("substrate: derived corpus %q requires provenance.producer", corpus)
	}
	if def.Archetype == Curated {
		e.Provenance = nil
	}

	now := p.now().UTC()
	e.ID = uuid.New() // random v4: entries are documents, not facts (§2.3)
	e.Namespace, e.Corpus = ns, corpus
	e.Tags = canonicalTags(e.Tags)
	e.Revision = 1
	e.Supersedes = uuid.Nil
	e.SignedOffBy = nil
	e.Created, e.Updated = now, now
	e.RetiredAt, e.SupersededAt = nil, nil
	if def.Archetype == Curated && def.Governance == Gated {
		e.Status = StatusDraft
		e.PublishedAt = nil
	} else {
		e.Status = StatusPublished
		e.PublishedAt = &now
	}
	e.ContentHash, err = hashContent(Content{Title: e.Title, Body: e.Body, Tags: e.Tags, Meta: e.Meta, Advice: e.Advice})
	if err != nil {
		return Entry{}, err
	}
	e.HashVersion = HashVersionV1

	err = p.inTx(ctx, func(tx *sql.Tx) error {
		if err := insertEntry(ctx, tx, e); err != nil {
			return err
		}
		return p.embedEntry(ctx, tx, e)
	})
	if err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Revise creates revision N+1 as a new row and marks the prior superseded.
// The prior revision's content stays hash-addressable (§4/§6).
func (p *Postgres) Revise(ctx context.Context, ns, corpus string, id uuid.UUID, r Revision) (Entry, error) {
	if err := validNamespace(ns); err != nil {
		return Entry{}, err
	}
	def, err := p.corpus(corpus)
	if err != nil {
		return Entry{}, err
	}
	if r.Title == "" || r.Body == "" {
		return Entry{}, fmt.Errorf("substrate: revision needs title and body")
	}

	var next Entry
	err = p.inTx(ctx, func(tx *sql.Tx) error {
		prior, err := getEntry(ctx, tx, ns, corpus, id, true)
		if err != nil {
			return err
		}
		if prior.SupersededAt != nil {
			return fmt.Errorf("%w: %s", ErrSuperseded, id)
		}
		now := p.now().UTC()
		next = prior
		next.ID = uuid.New()
		next.Title, next.Body, next.Advice = r.Title, r.Body, r.Advice
		next.Tags = canonicalTags(r.Tags)
		next.Meta = r.Meta
		next.VersionLabel = r.VersionLabel
		next.Revision = prior.Revision + 1
		next.Supersedes = prior.ID
		next.SignedOffBy = nil
		next.Created, next.Updated = now, now
		next.RetiredAt, next.SupersededAt = nil, nil
		if r.AuthoredBy != "" {
			next.AuthoredBy = r.AuthoredBy
		}
		if r.Provenance != nil {
			next.Provenance = r.Provenance
		}
		if def.Archetype == Curated && def.Governance == Gated {
			next.Status = StatusDraft
			next.PublishedAt = nil
		} else {
			next.Status = StatusPublished
			next.PublishedAt = &now
		}
		next.ContentHash, err = hashContent(Content{Title: next.Title, Body: next.Body, Tags: next.Tags, Meta: next.Meta, Advice: next.Advice})
		if err != nil {
			return err
		}
		next.HashVersion = HashVersionV1

		if err := insertEntry(ctx, tx, next); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE substrate_entries SET superseded_at = $1, updated = $1 WHERE id = $2`, now, prior.ID); err != nil {
			return fmt.Errorf("substrate: supersede prior revision: %w", err)
		}
		return p.embedEntry(ctx, tx, next)
	})
	if err != nil {
		return Entry{}, err
	}
	return next, nil
}

// Transition moves an entry through its governance state machine (§4). The
// store validates the machine, not the principal — entitlement is the
// deployment's concern.
func (p *Postgres) Transition(ctx context.Context, ns, corpus string, id uuid.UUID, t Transition) error {
	if err := validNamespace(ns); err != nil {
		return err
	}
	def, err := p.corpus(corpus)
	if err != nil {
		return err
	}
	return p.inTx(ctx, func(tx *sql.Tx) error {
		e, err := getEntry(ctx, tx, ns, corpus, id, true)
		if err != nil {
			return err
		}
		gated := def.Archetype == Curated && def.Governance == Gated
		allowed := false
		switch {
		case e.Status == StatusPublished && t.To == StatusRetired:
			allowed = true // the sole transition for LIGHTWEIGHT and DERIVED; also legal when gated
		case gated && e.Status == StatusDraft && t.To == StatusInReview:
			allowed = true
		case gated && e.Status == StatusInReview && t.To == StatusDraft:
			allowed = true // request-changes
		case gated && e.Status == StatusInReview && t.To == StatusPublished:
			if len(t.Principals) == 0 {
				return ErrSignerRequired
			}
			allowed = true
		}
		if !allowed {
			return fmt.Errorf("%w: %s → %s under %s/%s", ErrBadTransition, e.Status, t.To, def.Archetype, def.Governance)
		}
		now := p.now().UTC()
		var pubAt, retAt any
		pubAt, retAt = e.PublishedAt, e.RetiredAt
		var signers any = pq.Array(e.SignedOffBy)
		switch t.To {
		case StatusPublished:
			pubAt = now
			signers = pq.Array(t.Principals) // the substrate records the signoff (§4)
		case StatusRetired:
			retAt = now
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE substrate_entries
			 SET status = $1, published_at = $2, retired_at = $3, signed_off_by = $4, updated = $5
			 WHERE id = $6`,
			string(t.To), pubAt, retAt, signers, now, id); err != nil {
			return fmt.Errorf("substrate: transition: %w", err)
		}
		return nil
	})
}

// Purge removes content and its snapshots for compliance (§4), leaving a
// tombstone keyed by the hash so attestation answers honestly.
func (p *Postgres) Purge(ctx context.Context, ns, corpus string, id uuid.UUID) error {
	if err := validNamespace(ns); err != nil {
		return err
	}
	if _, err := p.corpus(corpus); err != nil {
		return err
	}
	return p.inTx(ctx, func(tx *sql.Tx) error {
		e, err := getEntry(ctx, tx, ns, corpus, id, true)
		if err != nil {
			return err
		}
		now := p.now().UTC()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO substrate_tombstones (namespace, content_hash, hash_version, purged_at)
			 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			ns, string(e.ContentHash), e.HashVersion, now); err != nil {
			return fmt.Errorf("substrate: write tombstone: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM substrate_entries WHERE id = $1`, id); err != nil {
			return fmt.Errorf("substrate: purge entry: %w", err)
		}
		return nil
	})
}

// Get returns one entry by id within the namespace and corpus.
func (p *Postgres) Get(ctx context.Context, ns, corpus string, id uuid.UUID) (Entry, error) {
	if err := validNamespace(ns); err != nil {
		return Entry{}, err
	}
	if _, err := p.corpus(corpus); err != nil {
		return Entry{}, err
	}
	return getEntry(ctx, p.db, ns, corpus, id, false)
}

// List returns entries in the namespace and corpus, newest first. The zero
// filter returns current revisions only (no retired, no superseded).
func (p *Postgres) List(ctx context.Context, ns, corpus string, f ListFilter) ([]Entry, error) {
	if err := validNamespace(ns); err != nil {
		return nil, err
	}
	if _, err := p.corpus(corpus); err != nil {
		return nil, err
	}
	q := `SELECT ` + entryCols + ` FROM substrate_entries WHERE namespace = $1 AND corpus = $2`
	args := []any{ns, corpus}
	if f.Status != "" {
		args = append(args, string(f.Status))
		q += fmt.Sprintf(" AND status = $%d", len(args))
	} else if !f.IncludeRetired {
		q += ` AND status <> 'RETIRED'`
	}
	if f.Tag != "" {
		args = append(args, f.Tag)
		q += fmt.Sprintf(" AND $%d = ANY(tags)", len(args))
	}
	if !f.IncludeSuperseded {
		q += ` AND superseded_at IS NULL`
	}
	q += ` ORDER BY created DESC, id`
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if f.Offset > 0 {
		args = append(args, f.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args)) //nolint:gosec // G202: appends a positional placeholder; every value is parameterized
	}
	rows, err := p.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("substrate: list: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-side close
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Snapshot implements the §6 attestation lookup. Because revisions are rows
// and rows are never content-mutated, a live row IS the snapshot; only purged
// content falls through to the tombstone.
func (p *Postgres) Snapshot(ctx context.Context, ns string, hash ContentHash) (Snapshot, error) {
	if err := validNamespace(ns); err != nil {
		return Snapshot{}, err
	}
	row := p.db.QueryRowContext(ctx,
		`SELECT title, body, tags, meta, advice, hash_version FROM substrate_entries
		 WHERE namespace = $1 AND content_hash = $2 LIMIT 1`, ns, string(hash))
	var (
		c      Content
		advice sql.NullString
		meta   []byte
		hv     int
	)
	err := row.Scan(&c.Title, &c.Body, pq.Array(&c.Tags), &meta, &advice, &hv)
	switch {
	case err == nil:
		c.Advice = advice.String
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &c.Meta); err != nil {
				return Snapshot{}, fmt.Errorf("substrate: decode meta: %w", err)
			}
		}
		return Snapshot{Content: c, Hash: hash, HashVersion: hv}, nil
	case errors.Is(err, sql.ErrNoRows):
		// Fall through to the tombstone.
	default:
		return Snapshot{}, fmt.Errorf("substrate: snapshot: %w", err)
	}
	var (
		hvT      int
		purgedAt time.Time
	)
	err = p.db.QueryRowContext(ctx,
		`SELECT hash_version, purged_at FROM substrate_tombstones WHERE namespace = $1 AND content_hash = $2`,
		ns, string(hash)).Scan(&hvT, &purgedAt)
	switch {
	case err == nil:
		return Snapshot{Hash: hash, HashVersion: hvT, Purged: true, PurgedAt: &purgedAt}, nil
	case errors.Is(err, sql.ErrNoRows):
		return Snapshot{}, fmt.Errorf("%w: no content for hash %s", ErrNotFound, hash)
	default:
		return Snapshot{}, fmt.Errorf("substrate: snapshot tombstone: %w", err)
	}
}

// Reindex embeds every entry in the namespace that lacks a vector for the
// active model — the §10 migration path after a model switch, and the
// recovery path after embedder outages. Not part of the Store contract;
// operational surface on the concrete type. Returns the number embedded.
func (p *Postgres) Reindex(ctx context.Context, ns string) (int, error) {
	if p.embedder == nil {
		return 0, fmt.Errorf("substrate: reindex requires an embedder")
	}
	if err := validNamespace(ns); err != nil {
		return 0, err
	}
	rows, err := p.db.QueryContext(ctx,
		`SELECT e.id, e.title, e.body FROM substrate_entries e
		 WHERE e.namespace = $1 AND NOT EXISTS (
		   SELECT 1 FROM substrate_embeddings v WHERE v.entry_id = e.id AND v.model = $2)`,
		ns, p.embedder.Model())
	if err != nil {
		return 0, fmt.Errorf("substrate: reindex scan: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-side close
	type pending struct {
		id          uuid.UUID
		title, body string
	}
	var todo []pending
	for rows.Next() {
		var t pending
		if err := rows.Scan(&t.id, &t.title, &t.body); err != nil {
			return 0, fmt.Errorf("substrate: reindex scan: %w", err)
		}
		todo = append(todo, t)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for i, t := range todo {
		err := p.inTx(ctx, func(tx *sql.Tx) error {
			return p.embedEntry(ctx, tx, Entry{ID: t.id, Title: t.title, Body: t.body})
		})
		if err != nil {
			return i, fmt.Errorf("substrate: reindex %s: %w", t.id, err)
		}
	}
	return len(todo), nil
}

// embedEntry computes and upserts the entry's vector for the active model.
// No embedder configured = keyword-only deployment, nothing to do.
func (p *Postgres) embedEntry(ctx context.Context, tx *sql.Tx, e Entry) error {
	if p.embedder == nil {
		return nil
	}
	vecs, err := p.embedder.Embed(ctx, []string{embedText(e.Title, e.Body)})
	if err != nil {
		return fmt.Errorf("substrate: embed entry %s: %w", e.ID, err)
	}
	v := vecs[0]
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO substrate_embeddings (entry_id, model, dim, vec, created)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (entry_id, model) DO UPDATE SET dim = EXCLUDED.dim, vec = EXCLUDED.vec, created = EXCLUDED.created`,
		e.ID, p.embedder.Model(), len(v), pq.Array(v), p.now().UTC()); err != nil {
		return fmt.Errorf("substrate: store embedding for %s: %w", e.ID, err)
	}
	return nil
}

// embedText is what gets embedded: title and body — the ranked surface. Meta
// and advice are structure, not prose.
func embedText(title, body string) string { return title + "\n\n" + body }

func (p *Postgres) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("substrate: begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("substrate: commit: %w", err)
	}
	return nil
}

// entryCols is the scan order shared by every entry query.
const entryCols = `id, namespace, corpus, title, body, tags, meta, advice, status, revision,
	supersedes_ref, version_label, authored_by, signed_off_by,
	prov_producer, prov_producer_version, prov_generator_model, prov_source_ref,
	content_hash, hash_version, created, updated, published_at, retired_at, superseded_at`

type rowScanner interface{ Scan(dest ...any) error }

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getEntry(ctx context.Context, q querier, ns, corpus string, id uuid.UUID, forUpdate bool) (Entry, error) {
	query := `SELECT ` + entryCols + ` FROM substrate_entries WHERE id = $1 AND namespace = $2 AND corpus = $3`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	e, err := scanEntry(q.QueryRowContext(ctx, query, id, ns, corpus))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, fmt.Errorf("%w: %s in %s/%s", ErrNotFound, id, ns, corpus)
	}
	return e, err
}

func insertEntry(ctx context.Context, tx *sql.Tx, e Entry) error {
	var meta []byte
	if e.Meta != nil {
		var err error
		if meta, err = json.Marshal(e.Meta); err != nil {
			return fmt.Errorf("substrate: encode meta: %w", err)
		}
	}
	var supersedes any
	if e.Supersedes != uuid.Nil {
		supersedes = e.Supersedes
	}
	var prov Provenance
	if e.Provenance != nil {
		prov = *e.Provenance
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO substrate_entries (`+entryCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
		e.ID, e.Namespace, e.Corpus, e.Title, e.Body, pq.Array(e.Tags), nullableBytes(meta), nullStr(e.Advice),
		string(e.Status), e.Revision, supersedes, nullStr(e.VersionLabel), nullStr(e.AuthoredBy),
		pq.Array(e.SignedOffBy),
		nullStr(prov.Producer), nullStr(prov.ProducerVersion), nullStr(prov.GeneratorModel), nullStr(prov.SourceRef),
		string(e.ContentHash), e.HashVersion, e.Created, e.Updated, e.PublishedAt, e.RetiredAt, e.SupersededAt)
	if err != nil {
		return fmt.Errorf("substrate: insert entry: %w", err)
	}
	return nil
}

// scanEntry scans one entryCols row; extra receives any trailing columns the
// query appended (e.g. a rank score).
func scanEntry(r rowScanner, extra ...any) (Entry, error) {
	var (
		e                                    Entry
		meta                                 []byte
		advice, versionLabel, authoredBy     sql.NullString
		supersedes                           uuid.NullUUID
		signers                              pq.StringArray
		prodr, prodVer, genModel, sourceRef  sql.NullString
		hash                                 string
		publishedAt, retiredAt, supersededAt sql.NullTime
	)
	dests := []any{&e.ID, &e.Namespace, &e.Corpus, &e.Title, &e.Body, pq.Array(&e.Tags), &meta, &advice,
		(*string)(&e.Status), &e.Revision, &supersedes, &versionLabel, &authoredBy, &signers,
		&prodr, &prodVer, &genModel, &sourceRef,
		&hash, &e.HashVersion, &e.Created, &e.Updated, &publishedAt, &retiredAt, &supersededAt}
	dests = append(dests, extra...)
	err := r.Scan(dests...)
	if err != nil {
		return Entry{}, err
	}
	if len(meta) > 0 {
		if err := json.Unmarshal(meta, &e.Meta); err != nil {
			return Entry{}, fmt.Errorf("substrate: decode meta: %w", err)
		}
	}
	e.Advice = advice.String
	e.VersionLabel = versionLabel.String
	e.AuthoredBy = authoredBy.String
	e.SignedOffBy = signers
	if supersedes.Valid {
		e.Supersedes = supersedes.UUID
	}
	if prodr.Valid && prodr.String != "" {
		e.Provenance = &Provenance{
			Producer:        prodr.String,
			ProducerVersion: prodVer.String,
			GeneratorModel:  genModel.String,
			SourceRef:       sourceRef.String,
		}
	}
	e.ContentHash = ContentHash(hash)
	if publishedAt.Valid {
		t := publishedAt.Time
		e.PublishedAt = &t
	}
	if retiredAt.Valid {
		t := retiredAt.Time
		e.RetiredAt = &t
	}
	if supersededAt.Valid {
		t := supersededAt.Time
		e.SupersededAt = &t
	}
	return e, nil
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
