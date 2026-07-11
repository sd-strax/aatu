package temporal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/archive"
)

// ArchiveActivities are the side-effecting steps of the ArchiveInvestigation
// workflow (07 §2.3). They hold the aggregate handler (for the event store +
// projections), the tenant signing key, and the archive root. The whole
// load→build→sign→write runs in ONE activity: the bundle (with Layer B
// transcripts) can exceed Temporal's payload limit, so the bytes never cross
// the workflow boundary — only a small descriptor is returned.
type ArchiveActivities struct {
	handler    *aggregate.Handler
	signer     archive.Signer
	archiveDir string
}

// NewArchiveActivities constructs the archive activity set. archiveDir is the
// solo archive root (07 §2.4 default ~/.reckon/archive); bundles land under a
// per-tenant-namespace subdirectory.
func NewArchiveActivities(handler *aggregate.Handler, signer archive.Signer, archiveDir string) *ArchiveActivities {
	return &ArchiveActivities{handler: handler, signer: signer, archiveDir: archiveDir}
}

// ArchiveBundleInput is the frozen identity of the investigation to bundle.
type ArchiveBundleInput struct {
	GroupingID        string
	TenantID          string
	TenantNamespace   string
	IncludeSideStores bool
}

// ArchiveBundleOutput is the small descriptor the activity returns — the bundle
// bytes stay on disk.
type ArchiveBundleOutput struct {
	Path        string
	Filename    string
	ContentHash string
	SizeBytes   int
}

// ArchiveBundle loads a CONCLUDED investigation, builds + signs its export
// bundle, and writes it to the archive target (07 §2.3 steps 1–9). Idempotent
// enough to retry: it overwrites the same content-named path, and the bundle is
// a pure function of the (immutable, concluded) investigation.
func (a *ArchiveActivities) ArchiveBundle(ctx context.Context, in ArchiveBundleInput) (ArchiveBundleOutput, error) {
	// TenantNamespace becomes a path component under the archive root — require
	// a well-formed UUID so a crafted workflow input cannot traverse out of it.
	if _, err := uuid.Parse(in.TenantNamespace); err != nil {
		return ArchiveBundleOutput{}, fmt.Errorf("tenant namespace %q is not a valid uuid: %w", in.TenantNamespace, err)
	}

	inv, err := a.loadInvestigation(ctx, in)
	if err != nil {
		return ArchiveBundleOutput{}, err
	}

	res, err := archive.BuildBundle(inv, a.signer, time.Now().UTC())
	if err != nil {
		return ArchiveBundleOutput{}, err
	}

	// 07 §2.4 solo default: <archive-root>/<tenant-namespace>/<file>.tar.gz.
	// Written atomically (temp + rename): a crash mid-write must never leave a
	// truncated bundle at a legitimate-looking path for someone to trust later.
	// The filename is conclusion-time-derived (BuildBundle), so a retried
	// activity replaces the same file instead of accumulating siblings.
	dir := filepath.Join(a.archiveDir, in.TenantNamespace)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ArchiveBundleOutput{}, fmt.Errorf("create archive dir: %w", err)
	}
	path := filepath.Join(dir, res.Filename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, res.Bytes, 0o644); err != nil {
		return ArchiveBundleOutput{}, fmt.Errorf("write bundle %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return ArchiveBundleOutput{}, fmt.Errorf("finalize bundle %s: %w", path, err)
	}

	return ArchiveBundleOutput{
		Path:        path,
		Filename:    res.Filename,
		ContentHash: res.ContentHash,
		SizeBytes:   len(res.Bytes),
	}, nil
}

// loadInvestigation assembles the archive.Investigation from the event store +
// projections + side stores. It refuses a non-CONCLUDED investigation — an
// export bundle is a finalized artifact (07 §2).
func (a *ArchiveActivities) loadInvestigation(ctx context.Context, in ArchiveBundleInput) (archive.Investigation, error) {
	db := a.handler.DB()
	aggID, err := uuid.Parse(in.GroupingID)
	if err != nil {
		return archive.Investigation{}, fmt.Errorf("bad grouping id: %w", err)
	}

	ic, err := aggregate.LoadInvestigationCurrent(ctx, db, aggID)
	if err != nil {
		return archive.Investigation{}, fmt.Errorf("load investigation: %w", err)
	}
	if ic.Status != aggregate.StatusConcluded {
		return archive.Investigation{}, fmt.Errorf("investigation %s is %s, only a CONCLUDED investigation is exported", in.GroupingID, ic.Status)
	}

	// Event stream → events.jsonl (each event serialized in sequence order).
	stream, err := aggregate.NewStore(db).LoadStream(ctx, aggID)
	if err != nil {
		return archive.Investigation{}, fmt.Errorf("load event stream: %w", err)
	}
	events := make([]json.RawMessage, 0, len(stream))
	var summary string
	var concludedAt time.Time
	transcriptHashes := map[string]struct{}{}
	for i := range stream {
		raw, err := json.Marshal(stream[i])
		if err != nil {
			return archive.Investigation{}, fmt.Errorf("marshal event %d: %w", stream[i].SequenceNo, err)
		}
		events = append(events, raw)

		switch stream[i].Type {
		case aggregate.EventTypeConcluded:
			var p aggregate.InvestigationConcluded
			if err := json.Unmarshal(stream[i].Payload, &p); err == nil {
				summary = p.Summary
			}
			concludedAt = stream[i].OccurredAt
		case aggregate.EventTypeInterpretationRecorded:
			// Collect transcript content hashes so reasoning-only turns (no tool
			// call) still contribute their transcript to the bundle.
			var p aggregate.InterpretationRecorded
			if err := json.Unmarshal(stream[i].Payload, &p); err == nil && p.TranscriptRef != nil && p.TranscriptRef.ContentHash != "" {
				transcriptHashes[p.TranscriptRef.ContentHash] = struct{}{}
			}
		}
	}

	stixObjects, err := aggregate.ListReasoningStixPayloads(ctx, db, aggID)
	if err != nil {
		return archive.Investigation{}, err
	}
	hyps, err := aggregate.ListHypotheses(ctx, db, aggID)
	if err != nil {
		return archive.Investigation{}, err
	}
	actions, err := aggregate.ListActionSummaries(ctx, db, aggID)
	if err != nil {
		return archive.Investigation{}, err
	}

	inv := archive.Investigation{
		GroupingID:        in.GroupingID,
		Title:             ic.Title,
		Status:            ic.Status,
		Summary:           summary,
		ReportRef:         ic.ConclusionRef,
		TenantNamespace:   in.TenantNamespace,
		ConcludedAt:       concludedAt,
		Events:            events,
		StixObjects:       stixObjects,
		IncludeSideStores: in.IncludeSideStores,
	}
	for _, h := range hyps {
		inv.Hypotheses = append(inv.Hypotheses, archive.HypothesisSummary{
			ID: h.ID, Statement: h.Statement, Status: h.Status, Labels: h.Labels,
		})
	}
	for _, ac := range actions {
		inv.Actions = append(inv.Actions, archive.ActionSummary{
			ID: ac.ActionID.String(), ActionType: ac.ActionType, Tier: ac.Tier, Status: ac.Status,
		})
	}

	if in.IncludeSideStores {
		if err := a.loadSideStores(ctx, aggID, in.TenantID, transcriptHashes, &inv); err != nil {
			return archive.Investigation{}, err
		}
	}
	return inv, nil
}

// loadSideStores fills the bundle's Layer B content (07 §2.1 side-stores/):
// tool calls (by investigation) and transcripts (by content hash gathered from
// the reasoning events + tool-call rows).
func (a *ArchiveActivities) loadSideStores(ctx context.Context, aggID uuid.UUID, tenantID string, transcriptHashes map[string]struct{}, inv *archive.Investigation) error {
	db := a.handler.DB()

	rows, err := db.QueryContext(ctx, `
		SELECT tool_args, transcript_hash FROM ai_tool_calls WHERE investigation_id = $1 ORDER BY occurred_at, id
	`, aggID)
	if err != nil {
		return fmt.Errorf("query ai_tool_calls: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var args []byte
		var transcriptHash *string
		if err := rows.Scan(&args, &transcriptHash); err != nil {
			return fmt.Errorf("scan tool call: %w", err)
		}
		// Blob hash = content hash of the stored (byte-exact) args, so it matches
		// the event's tool_call_ref (D.2 stores normalized args byte-exact).
		inv.ToolCalls = append(inv.ToolCalls, archive.Blob{Hash: aggregate.HashContent(args), Bytes: args})
		if transcriptHash != nil && *transcriptHash != "" {
			transcriptHashes[*transcriptHash] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("bad tenant id: %w", err)
	}
	for hash := range transcriptHashes {
		var body []byte
		err := db.QueryRowContext(ctx,
			`SELECT body FROM ai_transcripts WHERE tenant_id = $1 AND hash = $2`, tid, hash).Scan(&body)
		if err != nil {
			// A referenced transcript that isn't in the store is a gap worth
			// surfacing, not silently dropping.
			return fmt.Errorf("transcript %s referenced but not stored: %w", hash, err)
		}
		inv.Transcripts = append(inv.Transcripts, archive.Blob{Hash: hash, Bytes: body})
	}
	return nil
}
