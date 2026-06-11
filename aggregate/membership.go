package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Membership event types (02-persistence.md §3). Unlike lifecycle transitions
// these are not paired with an InterpretationRecorded: MemberAdded/Removed are
// scope bookkeeping carrying their own rationale, and EvidenceAttached
// references an existing interpretation rather than producing a new one.
const (
	EventTypeMemberAdded      = "investigation.member_added"
	EventTypeMemberRemoved    = "investigation.member_removed"
	EventTypeEvidenceAttached = "investigation.evidence_attached"
)

// Evidence role and weight vocabularies (02-persistence.md §3; they map onto the
// x-supports / x-refutes edge vocabulary in 01-domain-model.md).
const (
	RoleSupports = "supports"
	RoleRefutes  = "refutes"

	WeightStrong   = "STRONG"
	WeightModerate = "MODERATE"
	WeightWeak     = "WEAK"
)

// MemberAdded brings an externally-existing STIX object into this
// investigation's scope (02-persistence.md §3). Only for external references —
// aggregate-internal nodes (Interpretations, x-actions) are members implicitly
// at creation, with no MemberAdded event.
type MemberAdded struct {
	StixObjectRef string `json:"stix_object_ref"`
	Rationale     string `json:"rationale,omitempty"`
}

// MemberRemoved soft-removes a member; historical membership is preserved by
// the event itself.
type MemberRemoved struct {
	StixObjectRef string `json:"stix_object_ref"`
	Reason        string `json:"reason,omitempty"`
}

// EvidenceAttached links an evidence reference to an interpretation with a
// supporting/refuting role and a weight (02-persistence.md §3).
type EvidenceAttached struct {
	EvidenceRef       string    `json:"evidence_ref"`
	InterpretationRef uuid.UUID `json:"interpretation_ref"`
	Role              string    `json:"role"`
	Weight            string    `json:"weight"`
}

// AddMember is the command for MemberAdded.
type AddMember struct {
	StixObjectRef string `json:"stix_object_ref"`
	Rationale     string `json:"rationale,omitempty"`
}

// Kind returns "AddMember".
func (AddMember) Kind() string { return "AddMember" }

// Validate requires a non-empty member reference.
func (c AddMember) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.StixObjectRef == "" {
		return errors.New("AddMember: StixObjectRef is required")
	}
	return nil
}

// RemoveMember is the command for MemberRemoved.
type RemoveMember struct {
	StixObjectRef string `json:"stix_object_ref"`
	Reason        string `json:"reason,omitempty"`
}

// Kind returns "RemoveMember".
func (RemoveMember) Kind() string { return "RemoveMember" }

// Validate requires a non-empty member reference.
func (c RemoveMember) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.StixObjectRef == "" {
		return errors.New("RemoveMember: StixObjectRef is required")
	}
	return nil
}

// AttachEvidence is the command for EvidenceAttached.
type AttachEvidence struct {
	EvidenceRef       string    `json:"evidence_ref"`
	InterpretationRef uuid.UUID `json:"interpretation_ref"`
	Role              string    `json:"role"`
	Weight            string    `json:"weight"`
}

// Kind returns "AttachEvidence".
func (AttachEvidence) Kind() string { return "AttachEvidence" }

// Validate checks the evidence reference, target interpretation, role, and
// weight against their vocabularies.
func (c AttachEvidence) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.EvidenceRef == "" {
		return errors.New("AttachEvidence: EvidenceRef is required")
	}
	if c.InterpretationRef == (uuid.UUID{}) {
		return errors.New("AttachEvidence: InterpretationRef is required")
	}
	if c.Role != RoleSupports && c.Role != RoleRefutes {
		return fmt.Errorf("AttachEvidence: Role %q is not one of %q/%q", c.Role, RoleSupports, RoleRefutes)
	}
	switch c.Weight {
	case WeightStrong, WeightModerate, WeightWeak:
	default:
		return fmt.Errorf("AttachEvidence: Weight %q is not STRONG/MODERATE/WEAK", c.Weight)
	}
	return nil
}

// membershipEvent builds a single membership domain event at the next sequence.
// Membership changes are rejected on a concluded investigation: per
// 01-domain-model.md §Extension 2 a concluded investigation admits only
// reversal / post-conclusion / linkage interpretations, not scope edits —
// reopen first. (Archived is already refused by applyCommand's terminal guard.)
func membershipEvent(env Envelope, state aggregateState, eventType string, payload any) ([]Event, error) {
	if state.Status == StatusConcluded {
		return nil, fmt.Errorf("cannot modify membership of concluded investigation %s; reopen first", env.AggregateID)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []Event{{
		AggregateID:   env.AggregateID,
		SequenceNo:    state.Seq + 1,
		TenantID:      env.TenantID,
		Type:          eventType,
		Payload:       raw,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}}, nil
}
