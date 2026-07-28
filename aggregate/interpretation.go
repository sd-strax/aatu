package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
)

// EventTypeInterpretationRecorded tags an event that records one reasoning act
// — an x-interpretation node (01-domain-model.md §Interpretation). Lifecycle
// transitions, linkages, and (later) action requests each pair their domain
// event with one of these in the same transaction, tied by correlation_id, so
// the reasoning thread can be reassembled from the event log.
const EventTypeInterpretationRecorded = "interpretation.recorded"

// Interpretation type tags (01-domain-model.md §Interpretation types). The
// lifecycle/conclusion tags are produced by the lifecycle slice; the action-*
// tags live in action.go; the reasoning tags below are authored by the agent
// loop via RecordInterpretation (Phase D).
const (
	InterpretationLifecycle  = "lifecycle"
	InterpretationConclusion = "conclusion"
)

// Reasoning interpretation type tags (01-domain-model.md §Interpretation types).
// These are the analytical acts the agent loop (or the analyst) authors directly
// through RecordInterpretation, as opposed to the lifecycle/action transitions
// that pair an interpretation with a domain event. RecordInterpretation admits
// exactly this set — a lifecycle/action tag must flow through its own command so
// the paired domain event and state transition are never bypassed.
const (
	InterpretationExtraction   = "extraction"
	InterpretationSighting     = "sighting"
	InterpretationEvidencePin  = "evidence-pin"
	InterpretationHypothesis   = "hypothesis"
	InterpretationSupport      = "support"
	InterpretationRefutation   = "refutation"
	InterpretationInconclusive = "inconclusive"
	InterpretationPrediction   = "prediction"
	InterpretationVerdict      = "verdict"
	InterpretationPivot        = "pivot"
	InterpretationOther        = "other"
)

// reasoningTypes is the set RecordInterpretation accepts. Keeping it a closed
// allowlist stops the agent from smuggling a lifecycle/action tag (which would
// record a transition interpretation with no matching domain event) through the
// free-form reasoning path.
var reasoningTypes = map[string]bool{
	InterpretationExtraction:   true,
	InterpretationSighting:     true,
	InterpretationEvidencePin:  true,
	InterpretationHypothesis:   true,
	InterpretationSupport:      true,
	InterpretationRefutation:   true,
	InterpretationInconclusive: true,
	InterpretationPrediction:   true,
	InterpretationVerdict:      true,
	InterpretationPivot:        true,
	InterpretationOther:        true,
}

// rationaleMaxRunes bounds the interpretation rationale (01-domain-model.md
// §Interpretation: "terse by design," proposed cap ~500 chars). Full transcript
// detail lives in the side store, not the rationale.
const rationaleMaxRunes = 500

// Bounds on the reference lists a single reasoning act may carry. InputRefs/
// OutputRefs/ToolCallRefs land in the event payload — the event log is not the
// bulk store, so a runaway agent turn must not bloat it. One reasoning act over
// dozens of nodes should be decomposed into multiple acts (or is an extraction
// batch that belongs upstream). Generous for real use, hard against abuse.
const (
	maxRefsPerInterpretation      = 100
	maxToolCallsPerInterpretation = 100

	// maxRefRunes bounds each individual ref/label string. Refs are STIX/OCSF
	// ids by contract — a 9MB "ref" is bulk masquerading as an id, and it would
	// land in the event payload.
	maxRefRunes = 256
)

// validateRefList checks every entry of a ref list is non-bulk.
func validateRefList(field string, refs []string) error {
	for _, r := range refs {
		if utf8.RuneCountInString(r) > maxRefRunes {
			return fmt.Errorf("RecordInterpretation: %s entry exceeds %d chars (refs are ids, not payloads)", field, maxRefRunes)
		}
	}
	return nil
}

// Confidence values (01-domain-model.md §Interpretation schema). Optional.
const (
	ConfidenceHigh   = "HIGH"
	ConfidenceMedium = "MEDIUM"
	ConfidenceLow    = "LOW"
)

// Derivation mode (01-domain-model.md §Interpretation schema): DIRECT = produced
// by a tool through the capability layer; INFERRED = derived/reasoned by the
// analyst or the AI delegate. Lifecycle transitions are reasoning acts, so
// INFERRED.
const (
	DerivationDirect   = "DIRECT"
	DerivationInferred = "INFERRED"
)

// InterpretationRecorded is the payload of an EventTypeInterpretationRecorded
// event: one recorded reasoning act. It is the event-log projection of the
// x-interpretation primitive; the full STIX node is materialized into the
// object store in Phase B. Recording it here keeps the reasoning thread
// reconstructable from events alone.
type InterpretationRecorded struct {
	InterpretationID   uuid.UUID `json:"interpretation_id"`
	InterpretationType string    `json:"interpretation_type"`
	DerivationMode     string    `json:"derivation_mode"`
	InputRefs          []string  `json:"input_refs,omitempty"`
	Summary            string    `json:"summary,omitempty"`

	// The fields below are populated by agent-authored reasoning acts
	// (RecordInterpretation, Phase D). They stay omitempty so the lifecycle/
	// action pairings that predate them serialize unchanged.
	OutputRefs    []string       `json:"output_refs,omitempty"`
	Confidence    string         `json:"confidence,omitempty"`
	TranscriptRef *TranscriptRef `json:"transcript_ref,omitempty"`
	ToolCallRefs  []ToolCallRef  `json:"tool_call_refs,omitempty"`

	// Reasoning-node content (Phase D.2): hypotheses and predictions are
	// OUTPUTS of interpretations (01-domain-model.md), so their creation and
	// status transitions ride on the interpretation event that produced them.
	// foldState folds these for transition legality; the ReasoningNodeProjector
	// materializes them into stix_objects + the *_current projections.
	Hypothesis           *HypothesisRecorded           `json:"hypothesis,omitempty"`
	HypothesisTransition *HypothesisTransitionRecorded `json:"hypothesis_transition,omitempty"`
	Prediction           *PredictionRecorded           `json:"prediction,omitempty"`
	PredictionTransition *PredictionTransitionRecorded `json:"prediction_transition,omitempty"`

	// Verdict content on a type=verdict act (01 §Verdict): the disposition of
	// record, folded (latest non-superseded wins) and projected onto
	// investigation_current.
	Verdict *VerdictRecorded `json:"verdict,omitempty"`
}

// interpretationEvent builds an InterpretationRecorded event for env at seqNo,
// sharing env's correlation_id with the domain event it is paired with. The
// caller mints interpID (so the paired domain event can reference it via a
// lifecycle_interpretation_ref) — reasoning acts are distinct and never
// deduplicated (unlike STIX entities, which are deterministic UUIDv5). That the
// mint is non-deterministic is fine: commands run once and the resulting event
// is immutable; replay re-applies the stored event, it does not re-run the
// command.
func interpretationEvent(env Envelope, seqNo int64, interpID uuid.UUID, itype, summary string, inputRefs []string) (Event, error) {
	payload, err := json.Marshal(InterpretationRecorded{
		InterpretationID:   interpID,
		InterpretationType: itype,
		DerivationMode:     DerivationInferred,
		InputRefs:          inputRefs,
		Summary:            summary,
	})
	if err != nil {
		return Event{}, err
	}
	return Event{
		AggregateID:   env.AggregateID,
		SequenceNo:    seqNo,
		TenantID:      env.TenantID,
		Type:          EventTypeInterpretationRecorded,
		Version:       schemaVersion,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}, nil
}

// RecordInterpretation records one free-standing reasoning act authored by the
// agent loop or the analyst (01-domain-model.md §Interpretation; 05 §3.4). Unlike
// the lifecycle/action interpretations — which pair with a domain event and a
// state transition — a reasoning interpretation IS the act: a hypothesis
// proposed, a sighting recognized, a pivot taken. It appends exactly one
// InterpretationRecorded event (derivation_mode INFERRED), optionally carrying
// the transcript + tool-call content that produced it into the side store
// (02 §6 Layer B), hashed and written in the same transaction.
//
// This is the command that makes the agent the legal author of x-interpretation
// (03 §1: "the agent loop is their only legal author"): it is on the
// AI_DELEGATED allowlist, is annotate-tier (T1), and can never touch action
// status or authorization.
type RecordInterpretation struct {
	InterpretationID   uuid.UUID `json:"interpretation_id"` // minted by the caller
	InterpretationType string    `json:"interpretation_type"`
	InputRefs          []string  `json:"input_refs,omitempty"`  // node ids reasoned over
	OutputRefs         []string  `json:"output_refs,omitempty"` // STIX nodes produced
	Rationale          string    `json:"rationale"`
	Confidence         string    `json:"confidence,omitempty"`

	// Transcript + ToolCalls carry the reasoning provenance into the side store
	// (02 §6 Layer B). Optional: an analyst-authored interpretation has neither;
	// an AI-authored one carries both. The bytes are content-addressed — the
	// event stores only the hash, this command carries the bytes to persist.
	Transcript *TranscriptContent `json:"transcript,omitempty"`
	ToolCalls  []ToolCallContent  `json:"tool_calls,omitempty"`

	// Reasoning-node payloads (Phase D.2). Hypotheses/predictions are outputs
	// of interpretations, so they ride on this command rather than having
	// commands of their own:
	//   type=hypothesis    → Hypothesis (create) XOR HypothesisRef (acknowledge)
	//   type=support       → HypothesisRef (→ SUPPORTED)
	//   type=refutation    → HypothesisRef (→ REFUTED)
	//   type=inconclusive  → HypothesisRef (→ INCONCLUSIVE, or ABANDONED via Abandoned)
	//   type=prediction    → Prediction (create) XOR PredictionRef+PredictionStatus
	//                        (+TestResultRefs) for the test outcome
	// All other types must carry none of these.
	Hypothesis       *HypothesisNode `json:"hypothesis,omitempty"`
	HypothesisRef    string          `json:"hypothesis_ref,omitempty"`
	Abandoned        bool            `json:"abandoned,omitempty"`
	Prediction       *PredictionNode `json:"prediction,omitempty"`
	PredictionRef    string          `json:"prediction_ref,omitempty"`
	PredictionStatus string          `json:"prediction_status,omitempty"`
	TestResultRefs   []string        `json:"test_result_refs,omitempty"`

	// Verdict payload for type=verdict (01 §Verdict). AIVerdictConfigRef is
	// the AI-verdict dial's stamp: the SERVER sets it — exclusively when the
	// tenant configuration enables AI verdicts — and the aggregate rejects an
	// AI-delegated verdict without it (structural default-deny; the ref rides
	// the event so the audit trail shows what authorized the delegate).
	Verdict            *VerdictNode `json:"verdict,omitempty"`
	AIVerdictConfigRef string       `json:"ai_verdict_config_ref,omitempty"`
}

// Kind returns "RecordInterpretation".
func (RecordInterpretation) Kind() string { return "RecordInterpretation" }

// Validate checks the envelope, a minted id, a reasoning-type tag (the closed
// allowlist — no lifecycle/action tag may slip through), a bounded rationale,
// and a valid optional confidence.
func (c RecordInterpretation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.InterpretationID == (uuid.UUID{}) {
		return errors.New("RecordInterpretation: InterpretationID is zero")
	}
	if !reasoningTypes[c.InterpretationType] {
		return fmt.Errorf("RecordInterpretation: %q is not a reasoning interpretation type", c.InterpretationType)
	}
	if c.Rationale == "" {
		return errors.New("RecordInterpretation: Rationale is required")
	}
	if utf8.RuneCountInString(c.Rationale) > rationaleMaxRunes {
		return fmt.Errorf("RecordInterpretation: Rationale exceeds %d chars (terse by design; detail belongs in the transcript)", rationaleMaxRunes)
	}
	switch c.Confidence {
	case "", ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		return fmt.Errorf("RecordInterpretation: invalid confidence %q", c.Confidence)
	}
	if len(c.InputRefs) > maxRefsPerInterpretation || len(c.OutputRefs) > maxRefsPerInterpretation {
		return fmt.Errorf("RecordInterpretation: input/output refs exceed %d (decompose into multiple reasoning acts)", maxRefsPerInterpretation)
	}
	if err := validateRefList("input_refs", c.InputRefs); err != nil {
		return err
	}
	if err := validateRefList("output_refs", c.OutputRefs); err != nil {
		return err
	}
	if err := validateRefList("test_result_refs", c.TestResultRefs); err != nil {
		return err
	}
	if len(c.ToolCalls) > maxToolCallsPerInterpretation {
		return fmt.Errorf("RecordInterpretation: tool calls exceed %d per reasoning act", maxToolCallsPerInterpretation)
	}
	for i := range c.ToolCalls {
		// A tool_call_ref without a call id is a dangling reference — the event
		// would carry a hash nothing can be correlated back to.
		if c.ToolCalls[i].CallID == "" {
			return fmt.Errorf("RecordInterpretation: tool call %d has no call_id", i)
		}
		if c.ToolCalls[i].ToolName == "" {
			return fmt.Errorf("RecordInterpretation: tool call %q has no tool_name", c.ToolCalls[i].CallID)
		}
	}
	if err := validateVerdictShape(c); err != nil {
		return err
	}
	return validateReasoningNodeShape(c)
}

// hasBlobs reports whether this interpretation carries side-store content that
// the Handler must persist (in the same transaction as the event).
func (c RecordInterpretation) hasBlobs() bool {
	return c.Transcript != nil || len(c.ToolCalls) > 0
}

// applyRecordInterpretation emits the single InterpretationRecorded event for a
// reasoning act. Legal while the investigation is not CONCLUDED/ARCHIVED —
// reasoning is annotate-tier and free pre-conclusion (04 §1); a concluded
// investigation must be reopened before new reasoning is recorded. The
// transcript/tool-call refs are computed here (pure SHA-256 of the carried
// bytes) so the event addresses exactly the content the SideStore persists.
func applyRecordInterpretation(env Envelope, state aggregateState, c RecordInterpretation) ([]Event, error) {
	switch state.Status {
	case StatusDraft, StatusActive, StatusPaused:
	default:
		return nil, fmt.Errorf("RecordInterpretation rejected: investigation %s is %s (reasoning requires a pre-conclusion state)", env.AggregateID, state.Status)
	}

	rec := InterpretationRecorded{
		InterpretationID:   c.InterpretationID,
		InterpretationType: c.InterpretationType,
		DerivationMode:     DerivationInferred,
		InputRefs:          c.InputRefs,
		Summary:            c.Rationale,
		OutputRefs:         c.OutputRefs,
		Confidence:         c.Confidence,
	}
	if c.Transcript != nil {
		rec.TranscriptRef = &TranscriptRef{
			TranscriptID: c.Transcript.TranscriptID,
			TurnID:       c.Transcript.TurnID,
			ContentHash:  HashContent(c.Transcript.Body),
		}
	}
	for i := range c.ToolCalls {
		// Hash the NORMALIZED args — the exact bytes WriteReasoningTx stores —
		// so the event's content address always verifies against the stored row.
		rec.ToolCallRefs = append(rec.ToolCallRefs, ToolCallRef{
			CallID:      c.ToolCalls[i].CallID,
			ContentHash: HashContent(normalizeArgs(c.ToolCalls[i].Args)),
		})
	}

	// Node-bearing types (hypothesis/support/refutation/inconclusive/prediction):
	// validate against folded node state and enrich the event with the node
	// content the projector materializes (D.2).
	if err := applyReasoningNodes(env, state, c, &rec); err != nil {
		return nil, err
	}
	// Verdict guards (01 §Verdict): pinned evidence required; AI-delegated
	// verdicts denied without the tenant-dial stamp.
	if err := applyVerdictAct(env, state, c, &rec); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return []Event{{
		AggregateID:   env.AggregateID,
		SequenceNo:    state.Seq + 1,
		TenantID:      env.TenantID,
		Type:          EventTypeInterpretationRecorded,
		Version:       schemaVersion,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}}, nil
}
