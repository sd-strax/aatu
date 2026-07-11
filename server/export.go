package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/temporal"
)

// pipelineStarter is the narrow seam the export endpoint needs from the Temporal
// dispatch client. *temporal.Client satisfies it; tests inject a fake to assert
// what the endpoint starts (notably that IncludeSideStores comes from policy).
type pipelineStarter interface {
	StartPostConclusionPipeline(ctx context.Context, in temporal.ArchiveInvestigationInput) (string, error)
}

// getPipelineStarter returns the test override when set, else the live dispatch
// client (nil when it isn't started, so the endpoint 503s cleanly).
func (b *Backend) getPipelineStarter() pipelineStarter {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pipelineOverride != nil {
		return b.pipelineOverride
	}
	if b.dispatchClient == nil {
		return nil
	}
	return b.dispatchClient
}

// ExportResponse reports the triggered post-conclusion export.
type ExportResponse struct {
	InvestigationRef string `json:"investigation_ref"`
	WorkflowID       string `json:"workflow_id"`
	Status           string `json:"status"` // "STARTED"
}

// exportInvestigation handles POST /api/investigations/{id}/export: the
// on-demand trigger for the post-conclusion pipeline (07 §2.3). It asserts the
// investigation is CONCLUDED (a bundle is a finalized artifact), then starts the
// durable PostConclusionPipeline. Whether Layer B side stores are included is a
// TENANT POLICY (ExportIncludeSideStores), never the requester's choice — a
// compliance deployment's redaction must hold regardless of who exports.
//
// The workflow id is derived from the grouping id, so a re-export while one is
// already running is rejected by Temporal rather than launching a second build;
// after completion, a re-export simply rebuilds the same (immutable) artifact.
func (b *Backend) exportInvestigation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	id, ok := investigationSubresourceID(r.URL.Path, "export")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	ic, err := aggregate.LoadInvestigationCurrent(r.Context(), b.cfg.Handler.DB(), id)
	if errors.Is(err, errNoRows()) {
		writeJSONError(w, http.StatusNotFound, "investigation not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load investigation: "+err.Error())
		return
	}
	if ic.Status != aggregate.StatusConcluded {
		writeJSONError(w, http.StatusConflict,
			"investigation is "+ic.Status+"; only a CONCLUDED investigation can be exported")
		return
	}

	// The pipeline runs durably on the Temporal worker; without the dispatch
	// client wired there is no way to start it.
	starter := b.getPipelineStarter()
	if starter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "export pipeline not available (temporal dispatch client not started)")
		return
	}

	wfID, err := starter.StartPostConclusionPipeline(r.Context(), b.exportInput(id))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "start export: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, ExportResponse{
		InvestigationRef: id.String(),
		WorkflowID:       wfID,
		Status:           "STARTED",
	})
}

// exportInput builds the pipeline input for one investigation, sourcing the
// side-store policy from config (never a caller). Shared by the on-demand
// endpoint and the auto-on-conclude trigger.
func (b *Backend) exportInput(id uuid.UUID) temporal.ArchiveInvestigationInput {
	return temporal.ArchiveInvestigationInput{
		GroupingID:        id.String(),
		TenantID:          module.SingleTenantUUID.String(),
		TenantNamespace:   b.cfg.TenantNamespace,
		IncludeSideStores: b.cfg.ExportIncludeSideStores,
	}
}

// autoExportStartTimeout bounds the pipeline-start call on the conclude path:
// long enough for a healthy Temporal round-trip, short enough that a hung
// frontend does not stall the conclude response (the call is best-effort).
const autoExportStartTimeout = 5 * time.Second

// autoExportOnConclude fires the post-conclusion pipeline after a committed
// conclude, when policy enables it and the dispatch client is wired. Returns
// the started workflow id, or "" when auto-export is off, unavailable, or
// failed to start. Best-effort (07 §2.3, default on): a failure is logged, not
// surfaced — the conclusion stands, and an operator can retrigger via
// POST .../export.
//
// The conclude is already committed when this runs, so the start must not be
// lost to a client disconnect: the request context is detached from
// cancellation (keeping its trace/values) and bounded by its own timeout.
func (b *Backend) autoExportOnConclude(ctx context.Context, id uuid.UUID) string {
	if !b.cfg.ExportAutoOnConclude {
		return ""
	}
	starter := b.getPipelineStarter()
	if starter == nil {
		//nolint:gosec // G706: id is a parsed uuid.UUID (fixed hex format), not free-form input
		log.Printf("investigation %s concluded but export pipeline is unavailable; export on demand", id)
		return ""
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), autoExportStartTimeout)
	defer cancel()
	wfID, err := starter.StartPostConclusionPipeline(ctx, b.exportInput(id))
	if err != nil {
		//nolint:gosec // G706: id is a parsed uuid.UUID (fixed hex format), not free-form input
		log.Printf("investigation %s: auto-export failed to start: %v", id, err)
		return ""
	}
	return wfID
}
