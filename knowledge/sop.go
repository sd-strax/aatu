// Package knowledge is the institutional-memory service (design/06) — the
// consumer-side half of the split with the memory substrate
// (knowledge/design/00-substrate.md): the substrate owns storage, recall,
// attestation, and similarity as a host-free mechanism; this package maps
// reckon's SOP domain onto it and translates results back. It reaches the
// substrate only through the substrate.Store interface, so the mechanism stays
// unaware of SOPs, tenants, or STIX.
//
// SOPs live in the substrate's `procedures` CURATED corpus. A SOP's external
// id is a stable lineage id carried in a reserved tag, so an edit becomes a
// substrate revision (prior content stays hash-addressable) while the id the
// server and audit trail reference never moves.
package knowledge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/knowledge/substrate"
)

// CorpusProcedures is the substrate corpus SOPs live in (CURATED, lightweight
// governance for v0 — published on write; gated authoring is the paid module).
const CorpusProcedures = "procedures"

// CorpusCaseSummaries is the DERIVED corpus of concluded-investigation
// summaries (design/06 §3) — populated by SummarizeForKnowledgeIndex (K3),
// declared here so both corpora are registered at construction.
const CorpusCaseSummaries = "case-summaries"

// lineageTagPrefix marks the reserved tag carrying a SOP's stable external id.
// It rides in the entry's tags (so it survives revision and is returned by
// recall, which does not carry meta), and is stripped from every user-facing
// tag list.
const lineageTagPrefix = "__sop_lineage:"

// SOP statuses (design/06 §2.1). Stored lowercase in the SOP shape; mapped to
// the substrate's uppercase entry status. Lightweight governance goes straight
// to published; gated governance (paid) walks draft → in_review → published.
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

// Store is the SOP corpus, backed by the memory substrate.
type Store struct {
	sub substrate.Store
}

// NewStore constructs a Store over a substrate whose `procedures` corpus is
// declared.
func NewStore(sub substrate.Store) *Store { return &Store{sub: sub} }

// ErrNotFound is returned when a SOP id doesn't exist (or is already retired
// for mutating ops).
var ErrNotFound = errors.New("sop not found")

// Create inserts a new SOP as revision 1 of a fresh lineage and returns its
// stable external id. Lightweight governance publishes on write; the passed
// Status is advisory in v0 (the procedures corpus is lightweight). AuthorID,
// if a Keycloak subject, is recorded as the entry's opaque author.
func (s *Store) Create(ctx context.Context, sop SOP) (uuid.UUID, error) {
	if sop.TenantID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("Create: tenant_id required")
	}
	if sop.Title == "" || sop.Body == "" {
		return uuid.Nil, fmt.Errorf("Create: title and body required")
	}
	lineage := uuid.New()
	_, err := s.sub.Put(ctx, sop.TenantID.String(), CorpusProcedures, substrate.Entry{
		Title:      sop.Title,
		Body:       sop.Body,
		Tags:       withLineage(sop.Tags, lineage),
		Advice:     sop.Recommendation,
		AuthoredBy: sop.AuthorID,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create sop: %w", err)
	}
	return lineage, nil
}

// Get returns the current revision of one SOP by its lineage id.
func (s *Store) Get(ctx context.Context, tenantID, id uuid.UUID) (SOP, error) {
	e, err := s.resolveCurrent(ctx, tenantID, id, true)
	if err != nil {
		return SOP{}, err
	}
	return toSOP(e, tenantID, id), nil
}

// List returns a tenant's SOPs (current revisions), newest first. Retired SOPs
// are excluded unless includeRetired.
func (s *Store) List(ctx context.Context, tenantID uuid.UUID, includeRetired bool) ([]SOP, error) {
	entries, err := s.sub.List(ctx, tenantID.String(), CorpusProcedures, substrate.ListFilter{IncludeRetired: includeRetired})
	if err != nil {
		return nil, fmt.Errorf("list sops: %w", err)
	}
	out := make([]SOP, 0, len(entries))
	for _, e := range entries {
		lineage, ok := lineageOf(e.Tags)
		if !ok {
			continue // an entry not written through this facade — skip, don't guess an id
		}
		out = append(out, toSOP(e, tenantID, lineage))
	}
	return out, nil
}

// Update replaces the editable fields of a SOP as a new revision, keeping its
// lineage id (the prior revision's content stays hash-addressable). A retired
// SOP cannot be updated.
func (s *Store) Update(ctx context.Context, tenantID, id uuid.UUID, title, body string, tags []string, recommendation string) error {
	e, err := s.resolveCurrent(ctx, tenantID, id, false)
	if err != nil {
		return err
	}
	_, err = s.sub.Revise(ctx, tenantID.String(), CorpusProcedures, e.ID, substrate.Revision{
		Title:      title,
		Body:       body,
		Tags:       withLineage(tags, id),
		Advice:     recommendation,
		AuthoredBy: e.AuthoredBy, // carry the original author forward
	})
	if err != nil {
		return fmt.Errorf("update sop: %w", err)
	}
	return nil
}

// Retire soft-deletes a SOP (status → retired). Retired SOPs stay retrievable
// only with include_retired for audit; the content stays hash-addressable.
func (s *Store) Retire(ctx context.Context, tenantID, id uuid.UUID) error {
	e, err := s.resolveCurrent(ctx, tenantID, id, false)
	if err != nil {
		return err
	}
	if err := s.sub.Transition(ctx, tenantID.String(), CorpusProcedures, e.ID, substrate.Transition{To: substrate.StatusRetired}); err != nil {
		return fmt.Errorf("retire sop: %w", err)
	}
	return nil
}

// resolveCurrent finds the current-revision entry for a lineage id via its
// reserved tag (an indexed hard-filter). includeRetired governs whether a
// retired SOP resolves — false for mutating ops, which then report ErrNotFound
// for a missing or retired SOP, matching the pre-substrate behavior.
func (s *Store) resolveCurrent(ctx context.Context, tenantID, id uuid.UUID, includeRetired bool) (substrate.Entry, error) {
	entries, err := s.sub.List(ctx, tenantID.String(), CorpusProcedures, substrate.ListFilter{
		Tag:            lineageTagPrefix + id.String(),
		IncludeRetired: includeRetired,
	})
	if err != nil {
		return substrate.Entry{}, fmt.Errorf("resolve sop: %w", err)
	}
	if len(entries) == 0 {
		return substrate.Entry{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return entries[0], nil
}

// withLineage appends the reserved lineage tag to a user tag list, dropping any
// reserved tags the caller may have echoed back from a prior read.
func withLineage(tags []string, lineage uuid.UUID) []string {
	out := stripReserved(tags)
	return append(out, lineageTagPrefix+lineage.String())
}

// stripReserved returns tags with reserved (double-underscore) entries removed
// — the user-facing view never sees the lineage carrier.
func stripReserved(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if !strings.HasPrefix(t, "__") {
			out = append(out, t)
		}
	}
	return out
}

// lineageOf extracts the lineage id from an entry's reserved tag.
func lineageOf(tags []string) (uuid.UUID, bool) {
	for _, t := range tags {
		if rest, ok := strings.CutPrefix(t, lineageTagPrefix); ok {
			if id, err := uuid.Parse(rest); err == nil {
				return id, true
			}
		}
	}
	return uuid.Nil, false
}

// sopStatus maps a substrate entry status to the SOP status string.
func sopStatus(st substrate.Status) string {
	switch st {
	case substrate.StatusPublished:
		return StatusPublished
	case substrate.StatusRetired:
		return StatusRetired
	case substrate.StatusInReview:
		return StatusInReview
	default:
		return StatusDraft
	}
}

// toSOP maps a substrate entry back to the SOP shape under its lineage id.
func toSOP(e substrate.Entry, tenantID, lineage uuid.UUID) SOP {
	sop := SOP{
		ID:             lineage,
		TenantID:       tenantID,
		Title:          e.Title,
		Body:           e.Body,
		Tags:           stripReserved(e.Tags),
		Status:         sopStatus(e.Status),
		Recommendation: e.Advice,
		AuthorID:       e.AuthoredBy,
		CreatedAt:      e.Created,
		UpdatedAt:      e.Updated,
		PublishedAt:    e.PublishedAt,
		RetiredAt:      e.RetiredAt,
	}
	if len(e.SignedOffBy) > 0 {
		sop.SignerID = e.SignedOffBy[0]
	}
	return sop
}
