package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
)

// InvestigationView is the JSON shape returned to clients.
type InvestigationView struct {
	AggregateID       string `json:"aggregate_id"`
	Title             string `json:"title"`
	Status            string `json:"status"`
	LastEventSequence int64  `json:"last_event_sequence"`

	// Verdict is the disposition of record (01 §Verdict), absent when none —
	// the honest zero: no stored "pending".
	Verdict *VerdictView `json:"verdict,omitempty"`
}

// VerdictView is the verdict fold as served.
type VerdictView struct {
	Disposition      string    `json:"disposition"`
	Rationale        string    `json:"rationale,omitempty"`
	VerdictAt        time.Time `json:"verdict_at"`
	InterpretationID string    `json:"interpretation_id,omitempty"`
}

// CreateInvestigationRequest is the body of POST /api/investigations.
type CreateInvestigationRequest struct {
	Title string `json:"title"`
}

// CreateInvestigationResponse is the body of a successful POST.
type CreateInvestigationResponse struct {
	InvestigationView
	NewSequenceNo int64 `json:"new_sequence_no"`
}

// listInvestigations renders all rows of investigation_current.
// Requires viewer or analyst or auditor (enforced by caller).
func (b *Backend) listInvestigations(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	rows, err := b.cfg.Handler.DB().QueryContext(r.Context(),
		`SELECT aggregate_id, title, status, last_event_sequence
		 FROM investigation_current
		 ORDER BY updated_at DESC LIMIT 200`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	var out []InvestigationView
	for rows.Next() {
		var v InvestigationView
		var id uuid.UUID
		if err := rows.Scan(&id, &v.Title, &v.Status, &v.LastEventSequence); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		v.AggregateID = id.String()
		out = append(out, v)
	}
	if out == nil {
		out = []InvestigationView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"investigations": out})
}

// getInvestigation loads a single investigation by aggregate_id.
func (b *Backend) getInvestigation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	id, ok := investigationIDFromPath(r.URL.Path)
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
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	view := InvestigationView{
		AggregateID:       ic.AggregateID.String(),
		Title:             ic.Title,
		Status:            ic.Status,
		LastEventSequence: ic.LastEventSequence,
	}
	if ic.VerdictDisposition != "" {
		view.Verdict = &VerdictView{
			Disposition:      ic.VerdictDisposition,
			Rationale:        ic.VerdictRationale,
			VerdictAt:        ic.VerdictAt.Time,
			InterpretationID: ic.VerdictInterpretationID.String(),
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// createInvestigation dispatches a CreateInvestigation command via the
// aggregate Handler. Returns 201 on success with the projection's view of
// the new aggregate.
func (b *Backend) createInvestigation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}

	var req CreateInvestigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeJSONError(w, http.StatusBadRequest, "title is required")
		return
	}

	env := newEnvelope(uuid.New(), aggregate.Actor{PrincipalID: claims.Subject}, commandNow())
	res, err := b.cfg.Handler.Handle(r.Context(), env, aggregate.CreateInvestigation{Title: req.Title})
	if err != nil {
		writeCommandError(w, "create investigation", err)
		return
	}
	b.publishDeltas(res)

	writeJSON(w, http.StatusCreated, CreateInvestigationResponse{
		InvestigationView: InvestigationView{
			AggregateID:       res.AggregateID.String(),
			Title:             req.Title,
			Status:            aggregate.StatusDraft,
			LastEventSequence: res.NewSequenceNo,
		},
		NewSequenceNo: res.NewSequenceNo,
	})
}

// publishDeltas fans a command's committed events out to subscribed WebSocket
// clients. Called after a successful Handle on the client-initiated write path
// (design/05-component-architecture.md §9). System-emitted events from Temporal
// workflows reach subscribers via the Postgres LISTEN/NOTIFY path (deferred to
// v1); see the hub doc comment.
func (b *Backend) publishDeltas(res aggregate.Result) {
	if b.hub == nil {
		return
	}
	for _, e := range res.AppliedEvents {
		b.hub.publish(Delta{
			Type:        "event",
			AggregateID: e.AggregateID.String(),
			EventType:   e.Type,
			SequenceNo:  e.SequenceNo,
			OccurredAt:  e.OccurredAt,
			Payload:     e.Payload,
		})
	}
}

// investigationIDFromPath parses the UUID out of `/investigations/{id}`.
// The /api prefix has already been stripped by the parent router.
func investigationIDFromPath(p string) (uuid.UUID, bool) {
	const prefix = "/investigations/"
	if !strings.HasPrefix(p, prefix) {
		return uuid.UUID{}, false
	}
	tail := strings.TrimPrefix(p, prefix)
	tail = strings.TrimSuffix(tail, "/")
	if strings.Contains(tail, "/") {
		// nested paths not supported yet
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(tail)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

// errNoRows returns sql.ErrNoRows. Wrapped so the import stays localized to
// this file rather than spread across handlers.
func errNoRows() error {
	return sqlNoRowsSentinel
}
