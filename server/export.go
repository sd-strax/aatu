package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
	if b.actionClient == nil {
		return nil
	}
	return b.actionClient
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
	id, ok := exportInvestigationID(r.URL.Path)
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

	wfID, err := starter.StartPostConclusionPipeline(r.Context(), temporal.ArchiveInvestigationInput{
		GroupingID:        id.String(),
		TenantID:          module.SingleTenantUUID.String(),
		TenantNamespace:   b.cfg.TenantNamespace,
		IncludeSideStores: b.cfg.ExportIncludeSideStores,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "start export: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ExportResponse{
		InvestigationRef: id.String(),
		WorkflowID:       wfID,
		Status:           "STARTED",
	})
}

// exportInvestigationID parses the id out of `/investigations/{id}/export`
// (the /api prefix is already stripped).
func exportInvestigationID(p string) (uuid.UUID, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 3 || parts[0] != "investigations" || parts[2] != "export" {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}
