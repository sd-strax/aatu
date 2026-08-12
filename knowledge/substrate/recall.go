package substrate

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Mode selects between the two recall shapes (§5): RANK for a short free-text
// query, SIMILARITY for a whole document ("here is a 3-page draft; what do we
// already have like it?").
type Mode string

const (
	ModeRank       Mode = "RANK"
	ModeSimilarity Mode = "SIMILARITY"
)

// Band classifies a SIMILARITY result (§5.4) — the contract; the numeric
// cutoffs behind it are calibrated per {backend, backend_version} and shift
// when the backend does. Consumers persist bands with the ranker attribution,
// never raw scores as thresholds.
type Band string

const (
	// BandNearDuplicate: substantially the same thing; a consolidation candidate.
	BandNearDuplicate Band = "NEAR_DUPLICATE"
	// BandRelated: same problem space; worth reading before proceeding.
	BandRelated Band = "RELATED"
	// BandDistinct: returned only to show the nearest neighbors are far away.
	BandDistinct Band = "DISTINCT"
)

// Coverage is the §5.5 verdict. Failures (backend down, corpus unknown,
// malformed query) are errors, never EMPTY — consumers are entitled to treat
// EMPTY as evidence of absence.
type Coverage string

const (
	CoverageComplete Coverage = "COMPLETE"
	CoverageEmpty    Coverage = "EMPTY"
)

// RecallQuery is one recall call (§5.1): one corpus, one mode.
type RecallQuery struct {
	Corpus         string
	Mode           Mode   // default RANK
	Query          string // RANK: short free text. SIMILARITY: a whole document.
	Tags           []string
	Limit          int // default 5
	IncludeRetired bool
}

// RecallHit is one ranked result (§5.2). Score is opaque and orders this
// response only.
type RecallHit struct {
	EntryID        uuid.UUID
	Revision       int
	Title          string
	Excerpt        string
	Score          float64
	Band           Band // SIMILARITY mode only
	MatchRationale string
	ContentHash    ContentHash
	HashVersion    int
	Tags           []string
	Advice         string
	Status         Status
}

// Ranker attributes a result set to the backend that produced it, for audit
// trails and band interpretation.
type Ranker struct {
	Backend        string
	BackendVersion string
}

// RecallResult is the §5.2 envelope.
type RecallResult struct {
	Results     []RecallHit
	Coverage    Coverage
	Ranker      Ranker
	RetrievalAt time.Time
}

// BandCutoffs are the cosine floors for the vector backend's bands. Part of
// the backend version's calibration (§5.4) — deployment-tunable via WithBands.
type BandCutoffs struct {
	NearDuplicate float64
	Related       float64
}

// DefaultBands is the vector backend's v1 calibration point: conservative
// floors for the OpenAI-compatible embedding families. Honest coarseness
// beats false precision — tune per deployment if a model's cosine
// distribution warrants it.
var DefaultBands = BandCutoffs{NearDuplicate: 0.92, Related: 0.75}

const (
	defaultRecallLimit = 5
	excerptRuneBudget  = 480
	// keywordSimilarityTerms bounds the tsquery a SIMILARITY document is
	// reduced to on the keyword backend — plainto_tsquery ANDs terms, so a
	// whole document would match nothing. Crude by design (§10 v0).
	keywordSimilarityTerms = 12
)

// Recall executes one query over one corpus (§5). With an embedder the
// vector backend ranks by cosine similarity under the active model; without
// one it degrades to the keyword backend and says so in the attribution.
func (p *Postgres) Recall(ctx context.Context, ns string, q RecallQuery) (RecallResult, error) {
	if err := validNamespace(ns); err != nil {
		return RecallResult{}, err
	}
	if _, err := p.corpus(q.Corpus); err != nil {
		return RecallResult{}, err
	}
	if strings.TrimSpace(q.Query) == "" {
		return RecallResult{}, fmt.Errorf("substrate: recall query must not be empty")
	}
	switch q.Mode {
	case "":
		q.Mode = ModeRank
	case ModeRank, ModeSimilarity:
	default:
		return RecallResult{}, fmt.Errorf("substrate: unknown recall mode %q", q.Mode)
	}
	if q.Limit <= 0 {
		q.Limit = defaultRecallLimit
	}
	if p.embedder != nil {
		return p.recallVector(ctx, ns, q)
	}
	return p.recallKeyword(ctx, ns, q)
}

// recallVector is the §10 v1 backend: exact cosine over the tag-filtered
// candidate set, in process. Corpora are hundreds-to-thousands of entries by
// design; brute force at that scale is microseconds, and an approximate index
// slots in behind this same signature if a corpus ever outgrows it.
func (p *Postgres) recallVector(ctx context.Context, ns string, q RecallQuery) (RecallResult, error) {
	qv, err := p.embedder.Embed(ctx, []string{q.Query})
	if err != nil {
		return RecallResult{}, fmt.Errorf("substrate: embed recall query: %w", err)
	}
	cands, err := p.candidates(ctx, ns, q)
	if err != nil {
		return RecallResult{}, err
	}
	ranker := Ranker{Backend: "vector-cosine", BackendVersion: "1/" + p.embedder.Model()}
	if len(cands) == 0 {
		return RecallResult{Coverage: CoverageEmpty, Ranker: ranker, RetrievalAt: p.now().UTC()}, nil
	}
	vecs, err := p.vectorsFor(ctx, cands)
	if err != nil {
		return RecallResult{}, err
	}
	type scored struct {
		e   Entry
		sim float64
	}
	ranked := make([]scored, 0, len(cands))
	for _, e := range cands {
		v, ok := vecs[e.ID]
		if !ok {
			// A published candidate the backend cannot rank is an error, never a
			// silent gap (§5.5) — the remedy is Reindex after a model switch.
			return RecallResult{}, fmt.Errorf("%w: entry %s under model %s", ErrNoEmbedding, e.ID, p.embedder.Model())
		}
		ranked = append(ranked, scored{e: e, sim: cosine(qv[0], v)})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].sim != ranked[j].sim {
			return ranked[i].sim > ranked[j].sim
		}
		return ranked[i].e.Created.After(ranked[j].e.Created) // recency tiebreak
	})
	if len(ranked) > q.Limit {
		ranked = ranked[:q.Limit]
	}
	hits := make([]RecallHit, 0, len(ranked))
	for _, s := range ranked {
		h := hitFrom(s.e, s.sim)
		matched := intersect(q.Tags, s.e.Tags)
		if q.Mode == ModeSimilarity {
			h.Band = p.band(s.sim)
			h.MatchRationale = rationaleText(fmt.Sprintf("cosine %.2f under %s — %s band", s.sim, p.embedder.Model(), h.Band), matched)
		} else {
			h.MatchRationale = rationaleText(fmt.Sprintf("cosine %.2f to the query under %s", s.sim, p.embedder.Model()), matched)
		}
		hits = append(hits, h)
	}
	return RecallResult{Results: hits, Coverage: CoverageComplete, Ranker: ranker, RetrievalAt: p.now().UTC()}, nil
}

// recallKeyword is the degraded §10 v0 backend: Postgres full-text. In
// SIMILARITY mode the document is reduced to its leading terms and bands are
// deliberately coarse — RELATED at best, never NEAR_DUPLICATE (§13: honest
// coarseness beats false precision).
func (p *Postgres) recallKeyword(ctx context.Context, ns string, q RecallQuery) (RecallResult, error) {
	text := q.Query
	if q.Mode == ModeSimilarity {
		words := strings.Fields(text)
		if len(words) > keywordSimilarityTerms {
			words = words[:keywordSimilarityTerms]
		}
		text = strings.Join(words, " ")
	}
	query := `SELECT ` + entryCols + `, ts_rank(fts, tsq) AS score
		 FROM substrate_entries, plainto_tsquery('english', $3) tsq
		 WHERE namespace = $1 AND corpus = $2 AND superseded_at IS NULL AND fts @@ tsq`
	args := []any{ns, q.Corpus, text}
	query += statusClause(q.IncludeRetired)
	if len(q.Tags) > 0 {
		args = append(args, pq.Array(q.Tags))
		query += fmt.Sprintf(" AND tags && $%d", len(args))
	}
	args = append(args, q.Limit)
	query += fmt.Sprintf(" ORDER BY score DESC, created DESC LIMIT $%d", len(args)) //nolint:gosec // G202: appends a positional placeholder; every value is parameterized

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return RecallResult{}, fmt.Errorf("substrate: keyword recall: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-side close
	var hits []RecallHit
	for rows.Next() {
		var score float64
		e, err := scanEntry(rows, &score)
		if err != nil {
			return RecallResult{}, err
		}
		h := hitFrom(e, score)
		matched := intersect(q.Tags, e.Tags)
		if q.Mode == ModeSimilarity {
			h.Band = BandRelated // the keyword backend never claims NEAR_DUPLICATE
			h.MatchRationale = rationaleText(fmt.Sprintf("keyword overlap (ts_rank %.3f) with the document's leading terms — RELATED band (coarse keyword backend)", score), matched)
		} else {
			h.MatchRationale = rationaleText(fmt.Sprintf("keyword match on title+body (ts_rank %.3f)", score), matched)
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return RecallResult{}, err
	}
	ranker := Ranker{Backend: "pg-fts", BackendVersion: "1"}
	cov := CoverageComplete
	if len(hits) == 0 {
		cov = CoverageEmpty
	}
	return RecallResult{Results: hits, Coverage: cov, Ranker: ranker, RetrievalAt: p.now().UTC()}, nil
}

// candidates loads the recallable entries: current revisions, published (plus
// retired only on request), tag hard-filtered (overlap) before ranking.
func (p *Postgres) candidates(ctx context.Context, ns string, q RecallQuery) ([]Entry, error) {
	query := `SELECT ` + entryCols + ` FROM substrate_entries
		 WHERE namespace = $1 AND corpus = $2 AND superseded_at IS NULL`
	args := []any{ns, q.Corpus}
	query += statusClause(q.IncludeRetired)
	if len(q.Tags) > 0 {
		args = append(args, pq.Array(q.Tags))
		query += fmt.Sprintf(" AND tags && $%d", len(args)) //nolint:gosec // G202: appends a positional placeholder; every value is parameterized
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("substrate: recall candidates: %w", err)
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

func statusClause(includeRetired bool) string {
	if includeRetired {
		return ` AND status IN ('PUBLISHED','RETIRED')`
	}
	return ` AND status = 'PUBLISHED'`
}

// vectorsFor fetches the active model's vectors for the candidate set.
func (p *Postgres) vectorsFor(ctx context.Context, cands []Entry) (map[uuid.UUID][]float32, error) {
	ids := make([]uuid.UUID, len(cands))
	for i, e := range cands {
		ids[i] = e.ID
	}
	rows, err := p.db.QueryContext(ctx,
		`SELECT entry_id, vec FROM substrate_embeddings WHERE model = $1 AND entry_id = ANY($2)`,
		p.embedder.Model(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("substrate: load vectors: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-side close
	out := make(map[uuid.UUID][]float32, len(cands))
	for rows.Next() {
		var (
			id  uuid.UUID
			vec pq.Float32Array
		)
		if err := rows.Scan(&id, &vec); err != nil {
			return nil, fmt.Errorf("substrate: scan vector: %w", err)
		}
		out[id] = vec
	}
	return out, rows.Err()
}

func (p *Postgres) band(sim float64) Band {
	switch {
	case sim >= p.bands.NearDuplicate:
		return BandNearDuplicate
	case sim >= p.bands.Related:
		return BandRelated
	default:
		return BandDistinct
	}
}

func hitFrom(e Entry, score float64) RecallHit {
	return RecallHit{
		EntryID:     e.ID,
		Revision:    e.Revision,
		Title:       e.Title,
		Excerpt:     excerpt(e.Body),
		Score:       score,
		ContentHash: e.ContentHash,
		HashVersion: e.HashVersion,
		Tags:        e.Tags,
		Advice:      e.Advice,
		Status:      e.Status,
	}
}

// excerpt is a rune-budgeted view over the hashed content (§5.6): the
// attestation claim attaches to the content the hash covers, not the excerpt.
func excerpt(body string) string {
	runes := []rune(body)
	if len(runes) <= excerptRuneBudget {
		return body
	}
	return string(runes[:excerptRuneBudget]) + "…"
}

func rationaleText(core string, matchedTags []string) string {
	if len(matchedTags) == 0 {
		return core
	}
	return core + fmt.Sprintf("; tags [%s] matched (hard filter)", strings.Join(matchedTags, ", "))
}

func intersect(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if inB[s] {
			out = append(out, s)
		}
	}
	return out
}

// cosine is exact cosine similarity; zero-norm inputs score 0.
func cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
