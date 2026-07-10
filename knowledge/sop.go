// Package knowledge is the institutional-memory service (design/06). v0 (Phase
// C.5) implements the SOP corpus: CRUD with lightweight authoring and keyword
// retrieval over Postgres full-text search. Embeddings, vector similarity, and
// the concluded-investigation summary corpus are v1+ (Phase G); the retrieval
// API shape is stable now and returns keyword matches until then.
package knowledge

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// SOP statuses (design/06 §2.1). Stored lowercase, matching the sops table.
// Lightweight governance goes straight to published; gated governance
// (paid module) walks draft → in_review → published → retired.
const (
	StatusDraft     = "draft"
	StatusInReview  = "in_review"
	StatusPublished = "published"
	StatusRetired   = "retired"
)

// SOP is one runbook entry — procedural guidance the LLM consults during
// reasoning (design/06 §2). The body is unparsed prose; the system never
// executes it. Identity is a tenant-scoped random UUID (SOPs are documents, not
// observable facts — deterministic identity doesn't apply, §2.1).
type SOP struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Title          string     `json:"title"`
	Body           string     `json:"body"`
	Tags           []string   `json:"tags"`
	Status         string     `json:"status"`
	Recommendation string     `json:"recommendation,omitempty"`
	AuthorID       string     `json:"author_id,omitempty"`
	SignerID       string     `json:"signer_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
}

// Store is the SOP corpus over reckon_knowledge.
type Store struct {
	db *sql.DB
}

// NewStore constructs a Store over the knowledge database handle.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Create inserts a new SOP. In lightweight governance the caller passes
// StatusPublished (write-it-use-it); gated governance passes StatusDraft. A
// zero ID is minted; a published SOP gets published_at stamped.
func (s *Store) Create(ctx context.Context, sop SOP) (uuid.UUID, error) {
	if sop.ID == uuid.Nil {
		sop.ID = uuid.New()
	}
	if sop.TenantID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("Create: tenant_id required")
	}
	if sop.Title == "" || sop.Body == "" {
		return uuid.Nil, fmt.Errorf("Create: title and body required")
	}
	if sop.Status == "" {
		sop.Status = StatusPublished
	}
	var publishedAt sql.NullTime
	if sop.Status == StatusPublished {
		publishedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sops (id, tenant_id, title, body, tags, status, recommendation,
		                  author_id, published_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, sop.ID, sop.TenantID, sop.Title, sop.Body, pq.Array(sop.Tags), sop.Status,
		nullStr(sop.Recommendation), nullUUID(sop.AuthorID), publishedAt)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert sop: %w", err)
	}
	return sop.ID, nil
}

// Get returns one SOP by id, or sql.ErrNoRows.
func (s *Store) Get(ctx context.Context, tenantID, id uuid.UUID) (SOP, error) {
	row := s.db.QueryRowContext(ctx, sopColumns+` FROM sops WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return scanSOP(row)
}

// List returns a tenant's SOPs, newest-updated first. Retired SOPs are excluded
// unless includeRetired.
func (s *Store) List(ctx context.Context, tenantID uuid.UUID, includeRetired bool) ([]SOP, error) {
	q := sopColumns + ` FROM sops WHERE tenant_id = $1`
	if !includeRetired {
		q += ` AND status <> '` + StatusRetired + `'`
	}
	q += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list sops: %w", err)
	}
	defer rows.Close()
	var out []SOP
	for rows.Next() {
		sop, err := scanSOP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sop)
	}
	return out, rows.Err()
}

// Update replaces the editable fields of a SOP and bumps updated_at.
func (s *Store) Update(ctx context.Context, tenantID, id uuid.UUID, title, body string, tags []string, recommendation string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sops SET title = $3, body = $4, tags = $5, recommendation = $6, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status <> $7
	`, tenantID, id, title, body, pq.Array(tags), nullStr(recommendation), StatusRetired)
	if err != nil {
		return fmt.Errorf("update sop: %w", err)
	}
	return oneRow(res, id)
}

// Retire soft-deletes a SOP (status → retired). Retired SOPs stay retrievable
// only with include_retired for audit.
func (s *Store) Retire(ctx context.Context, tenantID, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sops SET status = $3, retired_at = NOW(), updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status <> $3
	`, tenantID, id, StatusRetired)
	if err != nil {
		return fmt.Errorf("retire sop: %w", err)
	}
	return oneRow(res, id)
}

const sopColumns = `SELECT id, tenant_id, title, body, tags, status, recommendation,
	author_id, created_at, updated_at, published_at, retired_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanSOP(row scanner) (SOP, error) {
	var sop SOP
	var rec, author sql.NullString
	var published, retired sql.NullTime
	err := row.Scan(&sop.ID, &sop.TenantID, &sop.Title, &sop.Body, pq.Array(&sop.Tags),
		&sop.Status, &rec, &author, &sop.CreatedAt, &sop.UpdatedAt, &published, &retired)
	if err != nil {
		return SOP{}, err
	}
	sop.Recommendation = rec.String
	sop.AuthorID = author.String
	if published.Valid {
		sop.PublishedAt = &published.Time
	}
	if retired.Valid {
		sop.RetiredAt = &retired.Time
	}
	return sop, nil
}

func nullStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func nullUUID(s string) sql.NullString {
	// author_id is a UUID column; pass NULL for empty, else the string (pq casts).
	return sql.NullString{String: s, Valid: s != ""}
}

// oneRow returns ErrNotFound when an update matched no row.
func oneRow(res sql.Result, id uuid.UUID) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// ErrNotFound is returned when a SOP id doesn't exist (or is already retired for
// mutating ops).
var ErrNotFound = fmt.Errorf("sop not found")
