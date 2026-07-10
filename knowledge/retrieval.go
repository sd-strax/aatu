package knowledge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Coverage is retrieval's coarse outcome (design/06 §4.3), mirroring the
// capability-layer convention. EMPTY is meaningful evidence-of-absence: "we have
// no institutional procedure for this."
const (
	CoverageComplete = "COMPLETE" // executed and returned ≥1 result
	CoverageEmpty    = "EMPTY"    // executed over the indexed corpus, zero matches
)

// excerptRunes bounds a SOP excerpt. v0 uses a rune budget as a stand-in for the
// spec's 4000-token budget (§4.2); sub-document embedding for section extraction
// is Phase G.
const excerptRunes = 2000

// RecallRequest is the recall_sops query (design/06 §4). In v0 the scope is a
// tag hard-filter (techniques/entity-types collapse to tags until applies_to and
// embeddings arrive); query drives Postgres full-text ranking.
type RecallRequest struct {
	Query          string   `json:"query"`
	Tags           []string `json:"tags,omitempty"`
	Limit          int      `json:"limit"`
	IncludeRetired bool     `json:"include_retired"`
}

// SOPMatch is one ranked retrieval result (design/06 §4).
type SOPMatch struct {
	SOPID          uuid.UUID `json:"sop_id"`
	Title          string    `json:"title"`
	Excerpt        string    `json:"excerpt"`
	Score          float64   `json:"score"`
	MatchRationale string    `json:"match_rationale"`
	Tags           []string  `json:"tags,omitempty"`
	Recommendation string    `json:"recommendation,omitempty"`
	Status         string    `json:"status"`
}

// RecallResult is the recall_sops response envelope.
type RecallResult struct {
	Results     []SOPMatch `json:"results"`
	Coverage    string     `json:"coverage"`
	RetrievalAt time.Time  `json:"retrieval_at"`
}

const defaultRecallLimit = 5

// RecallSOPs ranks the tenant's SOPs against the request (design/06 §4). v0
// ranking: a tag hard-filter (overlap) then Postgres full-text ts_rank over
// title+body when a query is present, else recency. Vector similarity, recency
// boost, and signoff weight are Phase G refinements over this same API shape.
func (s *Store) RecallSOPs(ctx context.Context, tenantID uuid.UUID, req RecallRequest) (RecallResult, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = defaultRecallLimit
	}

	// Build the query. $1 tenant, $2 tags (NULL = no filter), $3 query text,
	// $4 limit. Every parameter is always referenced (with a ::type cast where a
	// clause is conditional) so Postgres can determine its type. A blank query
	// ranks by recency; a present query full-text ranks.
	var b strings.Builder
	b.WriteString(`
		SELECT id, title, body, tags, recommendation, status,
		       CASE WHEN $3 = '' THEN 0::real
		            ELSE ts_rank(to_tsvector('english', title || ' ' || body),
		                         plainto_tsquery('english', $3))
		       END AS score
		FROM sops
		WHERE tenant_id = $1
		  AND ($2::text[] IS NULL OR tags && $2::text[])
	`)
	if !req.IncludeRetired {
		b.WriteString(" AND status <> '" + StatusRetired + "'")
	}
	if req.Query != "" {
		b.WriteString(" AND to_tsvector('english', title || ' ' || body) @@ plainto_tsquery('english', $3)")
	}
	b.WriteString(" ORDER BY score DESC, updated_at DESC LIMIT $4")

	// NULL tags = no filter; a non-empty set = overlap filter.
	var tagsArg any
	if len(req.Tags) > 0 {
		tagsArg = pq.Array(req.Tags)
	}
	rows, err := s.db.QueryContext(ctx, b.String(), tenantID, tagsArg, req.Query, limit)
	if err != nil {
		return RecallResult{}, fmt.Errorf("recall_sops: %w", err)
	}
	defer rows.Close()

	res := RecallResult{Coverage: CoverageEmpty, RetrievalAt: time.Now().UTC()}
	for rows.Next() {
		var (
			m    SOPMatch
			body string
			rec  sql.NullString
		)
		if err := rows.Scan(&m.SOPID, &m.Title, &body, pq.Array(&m.Tags), &rec, &m.Status, &m.Score); err != nil {
			return RecallResult{}, err
		}
		m.Excerpt = excerpt(body)
		m.Recommendation = rec.String
		m.MatchRationale = rationale(req, m)
		res.Results = append(res.Results, m)
	}
	if err := rows.Err(); err != nil {
		return RecallResult{}, err
	}
	if len(res.Results) > 0 {
		res.Coverage = CoverageComplete
	}
	return res, nil
}

// excerpt truncates a SOP body to the rune budget on a word boundary.
func excerpt(body string) string {
	r := []rune(body)
	if len(r) <= excerptRunes {
		return body
	}
	cut := string(r[:excerptRunes])
	if i := strings.LastIndex(cut, " "); i > excerptRunes/2 {
		cut = cut[:i]
	}
	return cut + "…"
}

// rationale builds the v0 match_rationale (design/06 §4.1): a short prose
// explanation. Richer rationale (embedding similarity, outcome) is Phase G.
func rationale(req RecallRequest, m SOPMatch) string {
	parts := make([]string, 0, 3)
	if len(req.Tags) > 0 {
		if overlap := intersect(req.Tags, m.Tags); len(overlap) > 0 {
			parts = append(parts, "tags "+strings.Join(overlap, ", ")+" (hard filter)")
		}
	}
	if req.Query != "" {
		parts = append(parts, fmt.Sprintf("full-text score %.3f", m.Score))
	}
	if len(parts) == 0 {
		return "recency (no query or tag filter)"
	}
	return strings.Join(parts, "; ")
}

func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
