package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/knowledge"
	"github.com/sd-strax/reckon/module"
)

// SOPBody is the create/update payload for a SOP.
type SOPBody struct {
	Title          string   `json:"title"`
	Body           string   `json:"body"`
	Tags           []string `json:"tags,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

// recallSOPs handles POST /api/knowledge/recall_sops (design/06 §4): keyword
// retrieval over the SOP corpus. Any authenticated reader — the agent loop
// consults it during reasoning.
func (b *Backend) recallSOPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b.requireRolesOrDeny(w, r, anyReader, func(w http.ResponseWriter, r *http.Request) {
		var req knowledge.RecallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
			return
		}
		res, err := b.cfg.Knowledge.RecallSOPs(r.Context(), module.SingleTenantUUID, req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "recall_sops: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

// sopsCollection routes /api/sops: POST create (analyst), GET list (reader).
func (b *Backend) sopsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.createSOP)
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, anyReader, b.listSOPs)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// sopsItem routes /api/sops/{id}: GET (reader), PUT update (analyst),
// DELETE retire (analyst).
func (b *Backend) sopsItem(w http.ResponseWriter, r *http.Request) {
	id, ok := sopID(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		b.requireRolesOrDeny(w, r, anyReader, func(w http.ResponseWriter, r *http.Request) { b.getSOP(w, r, id) })
	case http.MethodPut:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) { b.updateSOP(w, r, id) })
	case http.MethodDelete:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) { b.retireSOP(w, r, id) })
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (b *Backend) createSOP(w http.ResponseWriter, r *http.Request) {
	var body SOPBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	claims, _ := authz.FromContext(r.Context())
	sop := knowledge.SOP{
		TenantID: module.SingleTenantUUID,
		Title:    body.Title, Body: body.Body, Tags: body.Tags,
		Recommendation: body.Recommendation,
		// Lightweight governance: published on write. author_id is set only when
		// the principal is a UUID (Keycloak sub); otherwise left NULL.
		Status:   knowledge.StatusPublished,
		AuthorID: uuidStringOrEmpty(claims.Subject),
	}
	id, err := b.cfg.Knowledge.Create(r.Context(), sop)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "create sop: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func (b *Backend) listSOPs(w http.ResponseWriter, r *http.Request) {
	includeRetired := r.URL.Query().Get("include_retired") == "true"
	sops, err := b.cfg.Knowledge.List(r.Context(), module.SingleTenantUUID, includeRetired)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list sops: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sops": sops})
}

func (b *Backend) getSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	sop, err := b.cfg.Knowledge.Get(r.Context(), module.SingleTenantUUID, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "sop not found")
		return
	}
	writeJSON(w, http.StatusOK, sop)
}

func (b *Backend) updateSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var body SOPBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	err := b.cfg.Knowledge.Update(r.Context(), module.SingleTenantUUID, id, body.Title, body.Body, body.Tags, body.Recommendation)
	if errors.Is(err, knowledge.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "sop not found or retired")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "update sop: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) retireSOP(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	err := b.cfg.Knowledge.Retire(r.Context(), module.SingleTenantUUID, id)
	if errors.Is(err, knowledge.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "sop not found or already retired")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "retire sop: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// anyReader is the role set that may read (viewer, analyst, auditor).
var anyReader = []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}

// sopID extracts and parses the {id} path segment of /api/sops/{id}.
func sopID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := strings.TrimPrefix(r.URL.Path, "/sops/")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid sop id")
		return uuid.Nil, false
	}
	return id, true
}

// uuidStringOrEmpty returns s if it parses as a UUID, else "" (the author_id
// column is UUID; a non-UUID principal is recorded as NULL for v0).
func uuidStringOrEmpty(s string) string {
	if _, err := uuid.Parse(s); err == nil {
		return s
	}
	return ""
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
