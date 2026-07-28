package aggregate

// Pinned evidence + verdict (01-domain-model.md INTERPRETATION → Pinned
// evidence / Verdict): two interpretation acts, deliberately NOT new
// primitives. A pin is curation — the cited input_refs are load-bearing; the
// pinned surface is a fold over non-superseded evidence-pin acts. The verdict
// is the disposition of record — revisable by appending; the latest
// non-superseded verdict act wins; absence is the honest zero (no stored
// "pending"). Un-pin is supersession (SupersedeInterpretation), never
// deletion.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Verdict dispositions (01). No PENDING value — an investigation with no
// verdict act has no verdict.
const (
	VerdictBenign     = "BENIGN"
	VerdictSuspicious = "SUSPICIOUS"
	VerdictMalicious  = "MALICIOUS"
)

// VerdictNode is the verdict payload carried on a RecordInterpretation of
// type "verdict". The rationale/evidence travel on the interpretation itself
// (Rationale required as always; InputRefs must be non-empty — no verdict
// without cited evidence).
type VerdictNode struct {
	Disposition string `json:"disposition"` // BENIGN | SUSPICIOUS | MALICIOUS
}

// VerdictRecorded is the verdict content on the InterpretationRecorded event.
// ConfigRef is present only on AI-delegated verdicts: the tenant-config dial
// that authorized the delegate to judge (01: the enabling config ref rides
// the audit event; default-deny + configurable opening, the 04 §4 family).
type VerdictRecorded struct {
	Disposition string `json:"disposition"`
	ConfigRef   string `json:"config_ref,omitempty"`
}

func validVerdictDisposition(d string) bool {
	switch d {
	case VerdictBenign, VerdictSuspicious, VerdictMalicious:
		return true
	}
	return false
}

// --- folded state ---------------------------------------------------------------

// verdictEntry is one verdict act in fold order. The disposition of record is
// the last entry not superseded.
type verdictEntry struct {
	InterpID    uuid.UUID
	Disposition string
	Superseded  bool
}

// CurrentVerdict returns the disposition of record, or "" when the
// investigation has no (non-superseded) verdict.
func (s aggregateState) CurrentVerdict() string {
	for i := len(s.Verdicts) - 1; i >= 0; i-- {
		if !s.Verdicts[i].Superseded {
			return s.Verdicts[i].Disposition
		}
	}
	return ""
}

// activePinCount counts non-superseded evidence pins.
func (s aggregateState) activePinCount() int {
	n := 0
	for _, active := range s.Pins {
		if active {
			n++
		}
	}
	return n
}

// --- supersession ---------------------------------------------------------------

// EventTypeInterpretationSuperseded tags a supersession (01 §Interpretation
// lifecycle and correction; 02 §3): the superseded act remains visible in the
// thread and is no longer the current view. This is how a pin is un-pinned
// and how any free-standing reasoning act is retracted. No deletion exists.
const EventTypeInterpretationSuperseded = "interpretation.superseded"

// InterpretationSupersededPayload is the event payload. SupersedingID is set
// when a replacement act was recorded in the same motion (correction);
// empty for a pure retraction (un-pin).
type InterpretationSupersededPayload struct {
	SupersededID   uuid.UUID `json:"superseded_id"`
	SupersededType string    `json:"superseded_type"`
	SupersedingID  uuid.UUID `json:"superseding_id,omitempty"`
	Reason         string    `json:"reason"`
}

// SupersedeInterpretation marks a previously recorded free-standing reasoning
// act as superseded. Only the free-standing reasoning types can be superseded
// on their own — an interpretation paired with a domain transition (lifecycle,
// action-*, conclusion) is the transition's record and cannot be retracted
// apart from it.
type SupersedeInterpretation struct {
	SupersededID uuid.UUID `json:"superseded_id"`
	Reason       string    `json:"reason"`
}

// Kind returns "SupersedeInterpretation".
func (SupersedeInterpretation) Kind() string { return "SupersedeInterpretation" }

// Validate checks the envelope, a target id, and a reason (the audit trail
// must say why the record's current view changed).
func (c SupersedeInterpretation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.SupersededID == (uuid.UUID{}) {
		return errors.New("SupersedeInterpretation: SupersededID is zero")
	}
	if c.Reason == "" {
		return errors.New("SupersedeInterpretation: Reason is required")
	}
	return nil
}

// applySupersedeInterpretation emits the supersession event. Guards: the
// target must exist, must not already be superseded, and must be a
// free-standing reasoning act; supersession is reasoning-correction, so it
// requires a pre-conclusion state like every other reasoning act.
func applySupersedeInterpretation(env Envelope, state aggregateState, c SupersedeInterpretation) ([]Event, error) {
	switch state.Status {
	case StatusDraft, StatusActive, StatusPaused:
	default:
		return nil, fmt.Errorf("SupersedeInterpretation rejected: investigation %s is %s (correction requires a pre-conclusion state)", env.AggregateID, state.Status)
	}
	itype, ok := state.Interpretations[c.SupersededID]
	if !ok {
		return nil, fmt.Errorf("SupersedeInterpretation rejected: interpretation %s does not exist", c.SupersededID)
	}
	if state.SupersededInterps[c.SupersededID] {
		return nil, fmt.Errorf("SupersedeInterpretation rejected: interpretation %s is already superseded", c.SupersededID)
	}
	if !reasoningTypes[itype] {
		return nil, fmt.Errorf("SupersedeInterpretation rejected: %s is a %s interpretation — transition records cannot be retracted apart from their domain event", c.SupersededID, itype)
	}

	payload, err := json.Marshal(InterpretationSupersededPayload{
		SupersededID:   c.SupersededID,
		SupersededType: itype,
		Reason:         c.Reason,
	})
	if err != nil {
		return nil, err
	}
	return []Event{{
		AggregateID:   env.AggregateID,
		SequenceNo:    state.Seq + 1,
		TenantID:      env.TenantID,
		Type:          EventTypeInterpretationSuperseded,
		Version:       schemaVersion,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}}, nil
}

// foldSupersession applies one supersession to the folded maps.
func foldSupersession(s *aggregateState, p InterpretationSupersededPayload) {
	s.SupersededInterps[p.SupersededID] = true
	if _, isPin := s.Pins[p.SupersededID]; isPin {
		s.Pins[p.SupersededID] = false
	}
	for i := range s.Verdicts {
		if s.Verdicts[i].InterpID == p.SupersededID {
			s.Verdicts[i].Superseded = true
		}
	}
}

// --- verdict / pin guards on RecordInterpretation --------------------------------

// validateVerdictShape runs the pure shape checks for the evidence-pin and
// verdict types (state-dependent legality lives in applyVerdictAct).
func validateVerdictShape(c RecordInterpretation) error {
	switch c.InterpretationType {
	case InterpretationEvidencePin:
		if len(c.InputRefs) == 0 {
			return errors.New("RecordInterpretation: an evidence-pin must cite what it pins (input_refs is empty)")
		}
		if c.Verdict != nil {
			return errors.New("RecordInterpretation: type evidence-pin must not carry a verdict payload")
		}
	case InterpretationVerdict:
		if c.Verdict == nil {
			return errors.New("RecordInterpretation: type verdict requires the verdict payload")
		}
		if !validVerdictDisposition(c.Verdict.Disposition) {
			return fmt.Errorf("RecordInterpretation: invalid verdict disposition %q (BENIGN | SUSPICIOUS | MALICIOUS)", c.Verdict.Disposition)
		}
		if len(c.InputRefs) == 0 {
			return errors.New("RecordInterpretation: no verdict without cited evidence (input_refs is empty)")
		}
	default:
		if c.Verdict != nil {
			return fmt.Errorf("RecordInterpretation: type %q must not carry a verdict payload", c.InterpretationType)
		}
		if c.AIVerdictConfigRef != "" {
			return fmt.Errorf("RecordInterpretation: type %q must not carry ai_verdict_config_ref", c.InterpretationType)
		}
	}
	return nil
}

// applyVerdictAct runs the state-dependent verdict guards and enriches the
// event payload. No-op for non-verdict types.
func applyVerdictAct(env Envelope, state aggregateState, c RecordInterpretation, rec *InterpretationRecorded) error {
	if c.InterpretationType != InterpretationVerdict {
		return nil
	}
	// No verdict without pinned evidence (01: the single most important gate —
	// a disposition must rest on curated evidence, not vibes).
	if state.activePinCount() == 0 {
		return errors.New("RecordInterpretation rejected: a verdict requires at least one pinned evidence item — pin the load-bearing findings first")
	}
	// The AI-verdict dial (01): structurally default-deny. An AI-delegated
	// verdict is legal ONLY when the caller stamped the enabling tenant-config
	// ref onto the command — the server sets it exclusively when the tenant
	// dial is on, so absent stamp + AI actor = denied, no matter the path.
	if env.Actor.IsAIDelegated() && c.AIVerdictConfigRef == "" {
		return errors.New("RecordInterpretation rejected: AI-delegated verdicts are denied by default; the tenant configuration dial (trust.ai_verdict) is not enabled")
	}
	rec.Verdict = &VerdictRecorded{Disposition: c.Verdict.Disposition}
	if env.Actor.IsAIDelegated() {
		rec.Verdict.ConfigRef = c.AIVerdictConfigRef
	}
	return nil
}
