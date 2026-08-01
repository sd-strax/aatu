package server

import (
	"database/sql"
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

	// Seed is the investigation's root (01 §Extension 1); absent on pre-seed
	// investigations. SeedSummary is the triage-queue display line.
	Seed        *SeedBody `json:"seed,omitempty"`
	SeedSummary string    `json:"seed_summary,omitempty"`

	// Triage cues (ui/06 §Tree view — "what needs me, now?"), list rows only:
	// actions still awaiting a human decision, and the soonest approval-window
	// deadline among them (the countdown outranks everything else).
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	PendingActions int        `json:"pending_actions,omitempty"`
	NearestExpiry  *time.Time `json:"nearest_expiry,omitempty"`
}

func seedBody(s *aggregate.Seed) *SeedBody {
	if s == nil {
		return nil
	}
	return &SeedBody{
		Type: s.Type, AlertID: s.AlertID, Source: s.Source,
		DetectionFindingRef: s.DetectionFindingRef, EntityRef: s.EntityRef,
		EntityIdentifier: s.EntityIdentifier, HypothesisStatement: s.HypothesisStatement,
	}
}

// VerdictView is the verdict fold as served.
type VerdictView struct {
	Disposition      string    `json:"disposition"`
	Rationale        string    `json:"rationale,omitempty"`
	VerdictAt        time.Time `json:"verdict_at"`
	InterpretationID string    `json:"interpretation_id,omitempty"`
}

// SeedBody is the client shape of the investigation's root (01 §Extension 1).
type SeedBody struct {
	Type                string `json:"type"` // alert | entity | question
	AlertID             string `json:"alert_id,omitempty"`
	Source              string `json:"source,omitempty"`
	DetectionFindingRef string `json:"detection_finding_ref,omitempty"`
	EntityRef           string `json:"entity_ref,omitempty"`
	EntityIdentifier    string `json:"entity_identifier,omitempty"`
	HypothesisStatement string `json:"hypothesis_statement,omitempty"`
}

// SeedInputBody is the raw analyst-typed seed (design/ui/02 §2.7): the value the
// analyst rooted on plus their confirmed kind. The server resolves it to a full
// seed — minting the STIX id for an entity — so the workbench never handles ids.
// Kind is "entity" | "question" (empty = infer); alerts carry an explicit Seed.
type SeedInputBody struct {
	Value string `json:"value"`
	Kind  string `json:"kind,omitempty"`
}

// CreateInvestigationRequest is the body of POST /api/investigations. Exactly
// one of Seed (a fully-formed root, e.g. an alert) or SeedInput (a raw typed
// value the server resolves) is supplied by the product; both absent is a
// pre-seed investigation. Title may be empty when a seed is present — it is
// derived from the seed's display line.
type CreateInvestigationRequest struct {
	Title     string         `json:"title"`
	Seed      *SeedBody      `json:"seed,omitempty"`
	SeedInput *SeedInputBody `json:"seed_input,omitempty"`
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
	// The pending subqueries feed the tree's needs-me-first ordering (ui/06):
	// REQUESTED / PENDING_SECONDARY are the statuses still awaiting a human.
	rows, err := b.cfg.Handler.DB().QueryContext(r.Context(),
		`SELECT i.aggregate_id, i.title, i.status, i.last_event_sequence,
		        COALESCE(i.seed_summary, ''), i.updated_at,
		        (SELECT COUNT(*) FROM action_current a
		          WHERE a.aggregate_id = i.aggregate_id
		            AND a.status IN ('REQUESTED', 'PENDING_SECONDARY')),
		        (SELECT MIN(a.expires_at) FROM action_current a
		          WHERE a.aggregate_id = i.aggregate_id
		            AND a.status IN ('REQUESTED', 'PENDING_SECONDARY'))
		 FROM investigation_current i
		 ORDER BY i.updated_at DESC LIMIT 200`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	var out []InvestigationView
	for rows.Next() {
		var v InvestigationView
		var id uuid.UUID
		var updatedAt time.Time
		var nearest sql.NullTime
		if err := rows.Scan(&id, &v.Title, &v.Status, &v.LastEventSequence, &v.SeedSummary,
			&updatedAt, &v.PendingActions, &nearest); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		v.AggregateID = id.String()
		v.UpdatedAt = &updatedAt
		if nearest.Valid {
			t := nearest.Time
			v.NearestExpiry = &t
		}
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
		Seed:              seedBody(ic.Seed),
		SeedSummary:       ic.SeedSummary,
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

	cmd := aggregate.CreateInvestigation{Title: strings.TrimSpace(req.Title)}
	// The workbench's seed surface (design/ui/02 §2.7) sends a raw typed value;
	// the server resolves it to a full seed here, minting the STIX id for an
	// entity so the analyst never handles ids. A fully-formed Seed (alerts)
	// bypasses resolution.
	switch {
	case req.SeedInput != nil && req.Seed == nil:
		resolved, err := resolveSeedInput(b.identityResolver(), req.SeedInput.Value, req.SeedInput.Kind)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "resolve seed: "+err.Error())
			return
		}
		seed := resolved.Seed
		cmd.Seed = &seed
		if cmd.Title == "" {
			cmd.Title = deriveSeedTitle(resolved.Display)
		}
	case req.Seed != nil:
		cmd.Seed = &aggregate.Seed{
			Type: req.Seed.Type, AlertID: req.Seed.AlertID, Source: req.Seed.Source,
			DetectionFindingRef: req.Seed.DetectionFindingRef, EntityRef: req.Seed.EntityRef,
			EntityIdentifier: req.Seed.EntityIdentifier, HypothesisStatement: req.Seed.HypothesisStatement,
		}
		if cmd.Title == "" {
			cmd.Title = deriveSeedTitle(cmd.Seed.Summary())
		}
	}
	if cmd.Title == "" {
		writeJSONError(w, http.StatusBadRequest, "title is required (or supply a seed to derive it from)")
		return
	}

	env := newEnvelope(uuid.New(), aggregate.Actor{PrincipalID: claims.Subject}, commandNow())
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		writeCommandError(w, "create investigation", err)
		return
	}
	b.publishDeltas(res)

	writeJSON(w, http.StatusCreated, CreateInvestigationResponse{
		InvestigationView: InvestigationView{
			AggregateID:       res.AggregateID.String(),
			Title:             cmd.Title,
			Status:            aggregate.StatusDraft,
			LastEventSequence: res.NewSequenceNo,
			Seed:              seedBody(cmd.Seed),
			SeedSummary:       seedSummaryOf(cmd.Seed),
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
