package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
)

// Pinned evidence + supersession (01 §Pinned evidence): the read surface for
// the pin fold, and the un-pin/retraction path. Pins are recorded through the
// ordinary POST /api/interpretations (type=evidence-pin).

// PinView is one pinned-evidence row. Superseded pins are served with the
// flag set — what was once considered load-bearing stays visible; the UI
// renders them struck, never absent.
type PinView struct {
	InterpretationID string    `json:"interpretation_id"`
	Finding          string    `json:"finding"`
	InputRefs        []string  `json:"input_refs"`
	Actor            string    `json:"actor"` // HUMAN | AI_DELEGATED | SYSTEM
	PinnedAt         time.Time `json:"pinned_at"`
	Superseded       bool      `json:"superseded,omitempty"`
}

// listInvestigationPins serves GET /api/investigations/{id}/pins. Any
// authenticated reader (enforced by the caller).
func (b *Backend) listInvestigationPins(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	invID, ok := investigationSubresourceID(r.URL.Path, "pins")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}
	pins, err := aggregate.ListEvidencePins(r.Context(), b.cfg.Handler.DB(), invID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list pins: "+err.Error())
		return
	}
	out := []PinView{}
	for _, p := range pins {
		kind := p.Actor.Kind
		if kind == "" {
			kind = aggregate.ActorHuman
		}
		out = append(out, PinView{
			InterpretationID: p.InterpretationID.String(),
			Finding:          p.Finding,
			InputRefs:        p.InputRefs,
			Actor:            kind,
			PinnedAt:         p.PinnedAt.Time,
			Superseded:       p.Superseded,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pins": out})
}

// SupersedeBody is the POST /api/interpretations/{id}/supersede request.
type SupersedeBody struct {
	InvestigationRef string `json:"investigation_ref"`
	Reason           string `json:"reason"`
}

// interpretationsItem routes the /api/interpretations/{id}/* sub-resources:
// POST .../supersede (un-pin/retraction — analyst role, both actor kinds:
// correction is annotate-tier) and GET .../transcript (the committed turn
// record — any reader; the transcript is the audit record).
func (b *Backend) interpretationsItem(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimSuffix(r.URL.Path, "/")
	if strings.HasSuffix(trimmed, "/supersede") {
		switch r.Method {
		case http.MethodPost:
			b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.supersedeInterpretation)
		default:
			methodNotAllowed(w, "POST")
		}
		return
	}
	if strings.HasSuffix(trimmed, "/transcript") {
		switch r.Method {
		case http.MethodGet:
			b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, b.getInterpretationTranscript)
		default:
			methodNotAllowed(w, "GET")
		}
		return
	}
	writeJSONError(w, http.StatusNotFound, "unknown interpretations sub-resource")
}

func (b *Backend) supersedeInterpretation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	interpID, ok := interpretationSubresourceID(r.URL.Path, "supersede")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid interpretation id in path")
		return
	}
	var body SupersedeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	invID, err := uuid.Parse(body.InvestigationRef)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "investigation_ref is not a valid id")
		return
	}

	env := newEnvelope(invID, actorFromClaims(claims), commandNow())
	res, err := b.cfg.Handler.Handle(r.Context(), env, aggregate.SupersedeInterpretation{
		SupersededID: interpID,
		Reason:       body.Reason,
	})
	if err != nil {
		writeCommandError(w, "supersede interpretation", err)
		return
	}
	b.publishDeltas(res)
	writeJSON(w, http.StatusOK, map[string]any{
		"superseded_id": interpID.String(),
		"sequence_no":   res.NewSequenceNo,
	})
}

// interpretationSubresourceID parses `/interpretations/{id}/<sub>` — the one
// parser for every interpretation sub-resource, so path handling cannot drift.
func interpretationSubresourceID(p, sub string) (uuid.UUID, bool) {
	const prefix = "/interpretations/"
	tail, ok := strings.CutPrefix(p, prefix)
	if !ok {
		return uuid.UUID{}, false
	}
	tail = strings.TrimSuffix(strings.TrimSuffix(tail, "/"), "/"+sub)
	id, err := uuid.Parse(tail)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}
