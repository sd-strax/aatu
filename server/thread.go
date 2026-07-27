package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sd-strax/reckon/aggregate"
)

// GET /api/investigations/{id}/thread — the chronological reasoning thread
// (design/13 §4: "interpretations chronological, with rationale and cited
// evidence"). The thread is reassembled from interpretation.recorded events
// alone: every domain transition (lifecycle, action.*) pairs one in the same
// transaction (01, 02 §3), so nothing that changed the investigation is
// missing, and nothing is duplicated. Ordered by sequence_no — the aggregate's
// authoritative order — never occurred_at (caller-supplied wall clock).

// ThreadActorView is who authored one reasoning act — the accountability
// surface of "AI is a delegate, never a principal": Principal is always the
// human, Kind says whether the AI (or the system) acted on their behalf.
type ThreadActorView struct {
	Principal string `json:"principal"`
	Kind      string `json:"kind"` // HUMAN | AI_DELEGATED | SYSTEM
	// Model names the LLM for AI-delegated acts (actor.delegate).
	Model string `json:"model,omitempty"`
}

// ThreadEntryView is one reasoning act in the thread.
type ThreadEntryView struct {
	SequenceNo         int64           `json:"sequence_no"`
	OccurredAt         time.Time       `json:"occurred_at"`
	Actor              ThreadActorView `json:"actor"`
	InterpretationID   string          `json:"interpretation_id"`
	InterpretationType string          `json:"interpretation_type"`
	Summary            string          `json:"summary"`
	Confidence         string          `json:"confidence,omitempty"`
	InputRefs          []string        `json:"input_refs,omitempty"`
	OutputRefs         []string        `json:"output_refs,omitempty"`
	// ToolCalls counts the act's recorded tool dispatches; HasTranscript
	// reports a committed transcript in the side store. Presence indicators —
	// the bodies stay in their stores.
	ToolCalls     int  `json:"tool_calls,omitempty"`
	HasTranscript bool `json:"has_transcript,omitempty"`
}

// listInvestigationThread serves the thread. Any authenticated reader
// (viewer/analyst/auditor — enforced by the caller).
func (b *Backend) listInvestigationThread(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	invID, ok := investigationSubresourceID(r.URL.Path, "thread")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	rows, err := b.cfg.Handler.DB().QueryContext(r.Context(),
		`SELECT sequence_no, occurred_at, actor, payload
		 FROM events
		 WHERE aggregate_id = $1 AND event_type = $2
		 ORDER BY sequence_no`,
		invID, aggregate.EventTypeInterpretationRecorded)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query thread: "+err.Error())
		return
	}
	defer rows.Close()

	out := []ThreadEntryView{}
	for rows.Next() {
		var seq int64
		var at time.Time
		var actorRaw, payloadRaw []byte
		if err := rows.Scan(&seq, &at, &actorRaw, &payloadRaw); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan thread: "+err.Error())
			return
		}
		var actor aggregate.Actor
		_ = json.Unmarshal(actorRaw, &actor)
		var rec aggregate.InterpretationRecorded
		if err := json.Unmarshal(payloadRaw, &rec); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "decode interpretation: "+err.Error())
			return
		}

		v := ThreadEntryView{
			SequenceNo:         seq,
			OccurredAt:         at,
			Actor:              threadActor(actor),
			InterpretationID:   rec.InterpretationID.String(),
			InterpretationType: rec.InterpretationType,
			Summary:            rec.Summary,
			Confidence:         rec.Confidence,
			InputRefs:          rec.InputRefs,
			OutputRefs:         rec.OutputRefs,
			ToolCalls:          len(rec.ToolCallRefs),
			HasTranscript:      rec.TranscriptRef != nil,
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "iterate thread: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"thread": out})
}

func threadActor(a aggregate.Actor) ThreadActorView {
	v := ThreadActorView{Principal: a.PrincipalID, Kind: a.Kind}
	if v.Kind == "" {
		v.Kind = aggregate.ActorHuman
	}
	if a.Delegate != nil {
		v.Model = a.Delegate.Model
	}
	return v
}
