package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
)

// RenameRequestBody changes an investigation's human-facing title.
type RenameRequestBody struct {
	Title string `json:"title"`
}

// RenameResponse reports the applied title + resulting sequence.
type RenameResponse struct {
	InvestigationRef string `json:"investigation_ref"`
	Title            string `json:"title"`
	SequenceNo       int64  `json:"sequence_no"`
}

// renameInvestigation handles POST /api/investigations/{id}/rename: change the
// title. Analyst role; the actor kind is derived from the JWT, so an AI delegate
// is barred by the aggregate's allowlist (rename is human curation), not only
// here. Shape-guard only — the aggregate owns legality (non-blank, not concluded).
func (b *Backend) renameInvestigation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	id, ok := investigationSubresourceID(r.URL.Path, "rename")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	var body RenameRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		writeJSONError(w, http.StatusBadRequest, "title is required")
		return
	}

	env := newEnvelope(id, actorFromClaims(claims), commandNow())
	res, err := b.cfg.Handler.Handle(r.Context(), env, aggregate.RenameInvestigation{Title: title})
	if err != nil {
		writeCommandError(w, "rename", err)
		return
	}
	b.publishDeltas(res)

	writeJSON(w, http.StatusOK, RenameResponse{
		InvestigationRef: id.String(),
		Title:            title,
		SequenceNo:       res.NewSequenceNo,
	})
}
