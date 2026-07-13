package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
)

// LifecycleRequestBody drives an investigation state transition (01 §Extension 2).
// Transition selects the command; Reason annotates the reversible moves;
// ReportRef + Summary are required by conclude (a conclusion needs a Report).
type LifecycleRequestBody struct {
	Transition string `json:"transition"` // activate|pause|resume|conclude|reopen|archive
	Reason     string `json:"reason,omitempty"`
	ReportRef  string `json:"report_ref,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

// LifecycleResponse reports the resulting status + sequence. ExportWorkflowID
// is set when a conclude fired the automatic export (07 §2.3), so the client
// can correlate/poll the pipeline; absent when auto-export is off, unavailable,
// or failed to start (POST .../export remains the manual retrigger).
type LifecycleResponse struct {
	InvestigationRef string `json:"investigation_ref"`
	Status           string `json:"status"`
	SequenceNo       int64  `json:"sequence_no"`
	ExportWorkflowID string `json:"export_workflow_id,omitempty"`
}

// investigationLifecycle handles POST /api/investigations/{id}/lifecycle: the
// analyst-driven state machine (create is its own route). Analyst role; the
// actor kind is derived from the JWT (so an AI delegate is barred from
// conclude/reopen/archive by the aggregate's allowlist, not just here). When
// the committed events carry InvestigationConcluded it fires the automatic
// export (07 §2.3), best-effort.
func (b *Backend) investigationLifecycle(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	id, ok := investigationSubresourceID(r.URL.Path, "lifecycle")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	var body LifecycleRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	cmd, err := lifecycleCommand(body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	env := newEnvelope(id, actorFromClaims(claims), commandNow())
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		writeCommandError(w, body.Transition, err)
		return
	}
	b.publishDeltas(res)

	resp := LifecycleResponse{
		InvestigationRef: id.String(),
		// The committed events are the authority on the resulting status —
		// never a transition→status table maintained here.
		Status:     aggregate.StatusAfter(res.AppliedEvents),
		SequenceNo: res.NewSequenceNo,
	}
	// Keyed on the persisted event, not the request verb, per 07 §2.3
	// ("triggered automatically on InvestigationConcluded") — any path that
	// commits the event through this handler fires the export.
	for _, e := range res.AppliedEvents {
		if e.Type == aggregate.EventTypeConcluded {
			resp.ExportWorkflowID = b.autoExportOnConclude(r.Context(), id)
			break
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// lifecycleCommand maps a transition verb to its aggregate command — the single
// enumeration of the verbs this endpoint accepts. The returned error is the
// endpoint's whole shape-guard surface: an unknown verb, or conclude without a
// report_ref. All other legality is the aggregate's.
func lifecycleCommand(body LifecycleRequestBody) (aggregate.Command, error) {
	switch body.Transition {
	case "activate":
		return aggregate.ActivateInvestigation{Reason: body.Reason}, nil
	case "pause":
		return aggregate.PauseInvestigation{Reason: body.Reason}, nil
	case "resume":
		return aggregate.ResumeInvestigation{Reason: body.Reason}, nil
	case "conclude":
		ref := strings.TrimSpace(body.ReportRef)
		if ref == "" {
			return nil, errors.New("conclude requires report_ref")
		}
		return aggregate.ConcludeInvestigation{ReportRef: ref, Summary: body.Summary}, nil
	case "reopen":
		return aggregate.ReopenInvestigation{Reason: body.Reason}, nil
	case "archive":
		return aggregate.ArchiveInvestigation{Reason: body.Reason}, nil
	default:
		return nil, fmt.Errorf("unknown transition %s", body.Transition)
	}
}
