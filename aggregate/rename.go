package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// EventTypeRenamed records a title change. A rename is metadata curation — not a
// lifecycle status transition and not a reasoning act — so, like the membership
// events, it is a single domain event with NO paired lifecycle Interpretation
// (the 01-domain-model.md §Extension 2 pairing invariant covers status
// transitions, which this is not). The title never enters the chronicle.
const EventTypeRenamed = "investigation.renamed"

// InvestigationRenamed is the payload for a title change. To is the new title;
// the prior title lives in the event log's earlier created/renamed events, so
// it is not duplicated here.
type InvestigationRenamed struct {
	To string `json:"to"`
}

// RenameInvestigation changes an investigation's human-facing title. The title
// is projection state (investigation_current), never aggregate decision state —
// no fold tracks it, and the projector applies the UPDATE. Human curation:
// deliberately off the AI allowlist (aiAllowed), so an AI delegate cannot rename.
type RenameInvestigation struct {
	Title string `json:"title"`
}

// Kind returns "RenameInvestigation".
func (RenameInvestigation) Kind() string { return "RenameInvestigation" }

// Validate requires a non-blank title. Whitespace-only is rejected here, at the
// single write path, so no caller can persist a title that is blank in all but
// bytes.
func (c RenameInvestigation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if strings.TrimSpace(c.Title) == "" {
		return errors.New("RenameInvestigation: Title is empty")
	}
	return nil
}

// renameEvent builds the single investigation.renamed domain event. A concluded
// investigation's record is settled — renaming is a live-investigation
// affordance (archived is already refused by applyCommand's terminal guard;
// concluded we refuse here for the same "settled record" reason, symmetric with
// membership edits).
func renameEvent(env Envelope, state aggregateState, c RenameInvestigation) ([]Event, error) {
	if state.Status == StatusConcluded {
		return nil, fmt.Errorf("cannot rename concluded investigation %s; reopen first", env.AggregateID)
	}
	payload, err := json.Marshal(InvestigationRenamed{To: strings.TrimSpace(c.Title)})
	if err != nil {
		return nil, err
	}
	return []Event{{
		AggregateID:   env.AggregateID,
		SequenceNo:    state.Seq + 1,
		TenantID:      env.TenantID,
		Type:          EventTypeRenamed,
		Version:       schemaVersion,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}}, nil
}
