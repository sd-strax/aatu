package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/authz"
)

// The comms/external-work read+act surface (Phase F, binding §4). Threads are
// OPENED by the action layer (a SUCCEEDED notify.* dispatch), never here;
// these routes serve the conversation state and record the analyst's acts on
// it: acknowledge, mark done, snooze, and the inbound-reply ingestion seam.

// CommsTrailView is one trail entry as served.
type CommsTrailView struct {
	Direction string    `json:"direction"`
	Author    string    `json:"author"`
	At        time.Time `json:"at"`
	Body      string    `json:"body"`
}

// CommsThreadView is one thread as served.
type CommsThreadView struct {
	ThreadID      string           `json:"thread_id"`
	ActionID      string           `json:"action_id"`
	ActionType    string           `json:"action_type"`
	Target        string           `json:"target"`
	Subject       string           `json:"subject,omitempty"`
	Status        string           `json:"status"`
	FollowUpHours int              `json:"follow_up_hours,omitempty"`
	FollowUps     int              `json:"follow_ups,omitempty"`
	UnackedReply  bool             `json:"unacked_reply,omitempty"`
	SentAt        time.Time        `json:"sent_at"`
	NextFollowUp  *time.Time       `json:"next_followup_at,omitempty"`
	Trail         []CommsTrailView `json:"trail,omitempty"`

	// Derived flags (computed at read time; §4: policies surface prompts,
	// never auto-fire).
	FollowUpDue         bool   `json:"follow_up_due,omitempty"`
	EscalationTriggered bool   `json:"escalation_triggered,omitempty"`
	EscalationPolicy    string `json:"escalation_policy,omitempty"`
}

// listInvestigationComms serves GET /api/investigations/{id}/comms.
func (b *Backend) listInvestigationComms(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Comms == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "comms layer not configured")
		return
	}
	invID, ok := investigationSubresourceID(r.URL.Path, "comms")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}
	threads, err := b.cfg.Comms.List(r.Context(), invID, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list comms: "+err.Error())
		return
	}
	out := make([]CommsThreadView, 0, len(threads))
	for _, t := range threads {
		v := CommsThreadView{
			ThreadID:            t.ThreadID.String(),
			ActionID:            t.ActionID.String(),
			ActionType:          t.ActionType,
			Target:              t.Target,
			Subject:             t.Subject,
			Status:              t.Status,
			FollowUpHours:       t.FollowUpHours,
			FollowUps:           t.FollowUps,
			UnackedReply:        t.UnackedReply,
			SentAt:              t.SentAt,
			FollowUpDue:         t.FollowUpDue,
			EscalationTriggered: t.EscalationTriggered,
			EscalationPolicy:    t.EscalationPolicy,
		}
		if t.NextFollowUpAt.Valid {
			nt := t.NextFollowUpAt.Time
			v.NextFollowUp = &nt
		}
		for _, e := range t.Trail {
			v.Trail = append(v.Trail, CommsTrailView(e))
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"threads": out})
}

// CommsInboundBody is POST /api/comms/inbound — the v0 ingestion seam for a
// reply. A real vendor webhook lands with its adapter (Phase E/F); until
// then, replies arrive via API (CLI, tests, demo tooling).
type CommsInboundBody struct {
	ThreadID string `json:"thread_id"`
	Author   string `json:"author"`
	Body     string `json:"body"`
}

// commsRoute routes /api/comms/inbound and /api/comms/{id}/(ack|done|snooze).
// Analyst role; the acting principal is always the JWT subject.
func (b *Backend) commsRoute(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Comms == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "comms layer not configured")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	p := strings.TrimSuffix(r.URL.Path, "/")
	if p == "/comms/inbound" {
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.commsInbound)
		return
	}
	rest, ok := strings.CutPrefix(p, "/comms/")
	if !ok {
		writeJSONError(w, http.StatusNotFound, "path must be /comms/inbound or /comms/{id}/{ack|done|snooze}")
		return
	}
	idStr, verb, ok := strings.Cut(rest, "/")
	threadID, perr := uuid.Parse(idStr)
	if !ok || perr != nil {
		writeJSONError(w, http.StatusBadRequest, "path must be /comms/{id}/{ack|done|snooze}")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
		b.commsAct(w, r, threadID, verb)
	})
}

func (b *Backend) commsInbound(w http.ResponseWriter, r *http.Request) {
	var body CommsInboundBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	threadID, err := uuid.Parse(body.ThreadID)
	if err != nil || strings.TrimSpace(body.Body) == "" {
		writeJSONError(w, http.StatusBadRequest, "thread_id (uuid) and body are required")
		return
	}
	author := strings.TrimSpace(body.Author)
	if author == "" {
		author = "external"
	}
	if err := b.cfg.Comms.Inbound(r.Context(), threadID, author, body.Body, time.Now()); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "recorded"})
}

func (b *Backend) commsAct(w http.ResponseWriter, r *http.Request, threadID uuid.UUID, verb string) {
	claims, _ := authz.FromContext(r.Context())
	now := time.Now()
	var err error
	switch verb {
	case "ack":
		err = b.cfg.Comms.Ack(r.Context(), threadID, claims.Subject, now)
	case "done":
		err = b.cfg.Comms.Done(r.Context(), threadID, claims.Subject, now)
	case "snooze":
		var body struct {
			Hours int `json:"hours"`
		}
		if derr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); derr != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request body: "+derr.Error())
			return
		}
		if body.Hours <= 0 {
			body.Hours = 24
		}
		err = b.cfg.Comms.Snooze(r.Context(), threadID, claims.Subject, body.Hours, now)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown comms act "+verb)
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": verb})
}
