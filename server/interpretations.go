package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/module"
)

// RecordInterpretationBody is the /api/interpretations request: one reasoning
// act the agent loop (or analyst) is committing to the thread (05 §3.4 — the
// extension posts the final Interpretation command plus the transcript bytes;
// the backend hashes the bytes, writes the side store, and appends the event in
// one transaction).
type RecordInterpretationBody struct {
	InvestigationRef   string           `json:"investigation_ref"`
	InterpretationType string           `json:"interpretation_type"`
	InputRefs          []string         `json:"input_refs,omitempty"`
	OutputRefs         []string         `json:"output_refs,omitempty"`
	Rationale          string           `json:"rationale"`
	Confidence         string           `json:"confidence,omitempty"`
	Transcript         *TranscriptInput `json:"transcript,omitempty"`
	ToolCalls          []ToolCallInput  `json:"tool_calls,omitempty"`
}

// TranscriptInput carries the raw transcript for the turn. Body is the text as a
// string (LLM transcripts are text); it is hashed server-side into the content
// address stored on the event.
type TranscriptInput struct {
	TranscriptID string `json:"transcript_id,omitempty"`
	TurnID       string `json:"turn_id,omitempty"`
	Body         string `json:"body"`
}

// ToolCallInput is one tool dispatch the LLM made during the turn.
type ToolCallInput struct {
	CallID     string          `json:"call_id"`
	ToolName   string          `json:"tool_name"`
	Args       json.RawMessage `json:"args,omitempty"`
	ResultHash string          `json:"result_hash,omitempty"`
}

// RecordInterpretationResponse reports the appended interpretation.
type RecordInterpretationResponse struct {
	InterpretationID string `json:"interpretation_id"`
	SequenceNo       int64  `json:"sequence_no"`
}

// interpretationsCollection routes /api/interpretations. POST records a
// reasoning act; requires the analyst role — the AI authors interpretations on
// an analyst's behalf, never as a principal (the delegate is stamped from the
// JWT, the principal is the analyst).
func (b *Backend) interpretationsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.recordInterpretation)
	default:
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// recordInterpretation handles POST /api/interpretations: the agent loop's write
// into the reasoning thread (the legal-author seam, 03 §1). It mints the
// interpretation id, derives Actor.Kind from the JWT delegate_kind claim (never
// the body), and appends the InterpretationRecorded event together with its
// transcript/tool-call side store in one transaction.
func (b *Backend) recordInterpretation(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}

	var body RecordInterpretationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	investigationID, err := uuid.Parse(body.InvestigationRef)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "investigation_ref is not a valid id")
		return
	}

	// Actor.Kind comes from the JWT delegate_kind claim — NEVER the request body
	// (04 §5.6 seam obligation): otherwise an AI-authored interpretation could
	// masquerade as human-authored, or vice versa.
	actorKind := aggregate.ActorHuman
	var delegate *aggregate.AIDelegate
	if claims.DelegateKind != "" {
		actorKind = aggregate.ActorAIDelegated
		delegate = &aggregate.AIDelegate{Vendor: claims.DelegateKind}
	}

	cmd := aggregate.RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: body.InterpretationType,
		InputRefs:          body.InputRefs,
		OutputRefs:         body.OutputRefs,
		Rationale:          body.Rationale,
		Confidence:         body.Confidence,
	}
	if body.Transcript != nil {
		tID := uuid.New()
		if body.Transcript.TranscriptID != "" {
			if parsed, perr := uuid.Parse(body.Transcript.TranscriptID); perr == nil {
				tID = parsed
			}
		}
		cmd.Transcript = &aggregate.TranscriptContent{
			TranscriptID: tID,
			TurnID:       body.Transcript.TurnID,
			Body:         []byte(body.Transcript.Body),
		}
	}
	for _, tc := range body.ToolCalls {
		cmd.ToolCalls = append(cmd.ToolCalls, aggregate.ToolCallContent{
			CallID:     tc.CallID,
			ToolName:   tc.ToolName,
			Args:       tc.Args,
			ResultHash: tc.ResultHash,
		})
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	env := aggregate.Envelope{
		AggregateID:   investigationID,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		Actor:         aggregate.Actor{PrincipalID: claims.Subject, Kind: actorKind, Delegate: delegate},
		OccurredAt:    now,
	}
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "record interpretation: "+err.Error())
		return
	}
	b.publishDeltas(res)

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(RecordInterpretationResponse{
		InterpretationID: cmd.InterpretationID.String(),
		SequenceNo:       res.NewSequenceNo,
	})
}
