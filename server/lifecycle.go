package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/module"
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

// LifecycleResponse reports the resulting status + sequence.
type LifecycleResponse struct {
	InvestigationRef string `json:"investigation_ref"`
	Status           string `json:"status"`
	SequenceNo       int64  `json:"sequence_no"`
	ExportWorkflowID string `json:"export_workflow_id,omitempty"`
}

// lifecycleTransitions maps the request verb to the target status the projection
// will hold, used only to render the response (the aggregate is the authority on
// legality — it rejects an illegal transition from the current state).
var lifecycleTransitions = map[string]string{
	"activate": aggregate.StatusActive,
	"pause":    aggregate.StatusPaused,
	"resume":   aggregate.StatusActive,
	"conclude": aggregate.StatusConcluded,
	"reopen":   aggregate.StatusActive,
	"archive":  aggregate.StatusArchived,
}

// investigationLifecycle handles POST /api/investigations/{id}/lifecycle: the
// analyst-driven state machine (create is its own route). Analyst role; the
// actor kind is derived from the JWT (so an AI delegate is barred from
// conclude/reopen/archive by the aggregate's allowlist, not just here). On a
// successful conclude it fires the automatic export (07 §2.3), best-effort.
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
	id, ok := lifecycleInvestigationID(r.URL.Path)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	var body LifecycleRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	if _, known := lifecycleTransitions[body.Transition]; !known {
		writeJSONError(w, http.StatusBadRequest, "unknown transition "+body.Transition)
		return
	}
	cmd, ok := lifecycleCommand(body)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "conclude requires report_ref")
		return
	}

	env := aggregate.Envelope{
		AggregateID:   id,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		Actor:         actorFromClaims(claims),
		OccurredAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		// A rejected transition (wrong source state, missing report, AI barred
		// from conclude) is a 422 — the request was well-formed but illegal now.
		writeJSONError(w, http.StatusUnprocessableEntity, body.Transition+": "+err.Error())
		return
	}
	b.publishDeltas(res)

	resp := LifecycleResponse{
		InvestigationRef: id.String(),
		Status:           lifecycleTransitions[body.Transition],
		SequenceNo:       res.NewSequenceNo,
	}
	if body.Transition == "conclude" {
		// Auto-export fires here; the on-demand POST .../export remains available
		// for re-export or when auto is disabled.
		b.autoExportOnConclude(r.Context(), id)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// lifecycleCommand maps a transition to its aggregate command. Returns ok=false
// only for the one shape guard the endpoint owns (conclude needs a report_ref);
// all other legality is the aggregate's.
func lifecycleCommand(body LifecycleRequestBody) (aggregate.Command, bool) {
	switch body.Transition {
	case "activate":
		return aggregate.ActivateInvestigation{Reason: body.Reason}, true
	case "pause":
		return aggregate.PauseInvestigation{Reason: body.Reason}, true
	case "resume":
		return aggregate.ResumeInvestigation{Reason: body.Reason}, true
	case "conclude":
		if strings.TrimSpace(body.ReportRef) == "" {
			return nil, false
		}
		return aggregate.ConcludeInvestigation{ReportRef: body.ReportRef, Summary: body.Summary}, true
	case "reopen":
		return aggregate.ReopenInvestigation{Reason: body.Reason}, true
	case "archive":
		return aggregate.ArchiveInvestigation{Reason: body.Reason}, true
	default:
		return nil, false
	}
}

// lifecycleInvestigationID parses the id out of `/investigations/{id}/lifecycle`.
func lifecycleInvestigationID(p string) (uuid.UUID, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 3 || parts[0] != "investigations" || parts[2] != "lifecycle" {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}
