package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Sentinel causes threaded through command-rejection errors so callers (the
// HTTP layer foremost) can map them to distinct outcomes without parsing
// error strings. Both surface wrapped in a *RejectedError from Handle;
// errors.Is sees through the wrapping.
var (
	// ErrNotFound marks a command addressed to an aggregate that has no
	// events — the investigation does not exist.
	ErrNotFound = errors.New("investigation does not exist")

	// ErrAIDenied marks an AI_DELEGATED command outside the allowlist
	// (04 §5.6) — a permission denial, not a state-machine rejection.
	ErrAIDenied = errors.New("not in the AI_DELEGATED command allowlist (04 §5.6)")
)

// Command is anything that produces zero or more Events when applied to
// an aggregate. Implementations are pure values — Command does not own a
// transaction or know about the database. The Handler orchestrates
// transaction + event store + projection updates around it.
type Command interface {
	// Kind is a stable identifier for logging and event types.
	Kind() string
	// Validate runs envelope + command-shape checks. Returns nil if the
	// command is well-formed.
	Validate(env Envelope) error
}

// Seed is the investigation's root (01-domain-model.md §Extension 1) —
// adopted from IR methodology (NIST 800-61 precursor/indicator, TheHive):
// every case begins from an alert, an entity, or a question. Immutable, set
// at creation. reckon stores the POINTER to the thing in the external system
// (the not-a-SIEM stance): an AlertSeed references the tool's alert, never a
// copied queue row.
type Seed struct {
	Type string `json:"type"` // alert | entity | question

	// AlertSeed
	AlertID             string `json:"alert_id,omitempty"`
	Source              string `json:"source,omitempty"`
	DetectionFindingRef string `json:"detection_finding_ref,omitempty"`

	// EntitySeed
	EntityRef string `json:"entity_ref,omitempty"` // STIX SCO id

	// QuestionSeed (the hunt entry: hypothesis-rooted)
	HypothesisStatement string `json:"hypothesis_statement,omitempty"`
}

// Seed type tags.
const (
	SeedAlert    = "alert"
	SeedEntity   = "entity"
	SeedQuestion = "question"
)

// Summary renders the seed's one-line display form (the triage queue's
// "what is this case about?" column).
func (s Seed) Summary() string {
	switch s.Type {
	case SeedAlert:
		if s.Source != "" {
			return s.Source + ": " + s.AlertID
		}
		return s.AlertID
	case SeedEntity:
		return s.EntityRef
	case SeedQuestion:
		return s.HypothesisStatement
	}
	return ""
}

func (s Seed) validate() error {
	switch s.Type {
	case SeedAlert:
		if s.AlertID == "" || s.Source == "" {
			return errors.New("CreateInvestigation: an alert seed requires alert_id and source")
		}
	case SeedEntity:
		if s.EntityRef == "" {
			return errors.New("CreateInvestigation: an entity seed requires entity_ref")
		}
	case SeedQuestion:
		if s.HypothesisStatement == "" {
			return errors.New("CreateInvestigation: a question seed requires hypothesis_statement")
		}
	default:
		return fmt.Errorf("CreateInvestigation: unknown seed type %q (alert | entity | question)", s.Type)
	}
	return nil
}

// CreateInvestigation persists one investigation.created event. Seed is the
// investigation's root; optional at the engine layer (pre-seed investigations
// exist, and drivers like the eval harness supply context conversationally),
// but every product entry point supplies one — "never start from an empty
// chat" is a surface obligation the engine records, not enforces.
type CreateInvestigation struct {
	Title string `json:"title"`
	Seed  *Seed  `json:"seed,omitempty"`
}

// Kind returns "CreateInvestigation".
func (CreateInvestigation) Kind() string { return "CreateInvestigation" }

// Validate checks envelope completeness, title non-emptiness, and seed shape.
func (c CreateInvestigation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.Title == "" {
		return errors.New("CreateInvestigation: Title is empty")
	}
	if c.Seed != nil {
		return c.Seed.validate()
	}
	return nil
}

// validateEnvelope checks the request-time metadata every command requires.
// Shared by all commands so the envelope contract is defined once.
func validateEnvelope(env Envelope) error {
	if env.AggregateID == (AggregateID{}) {
		return ErrEnvelope("AggregateID is zero")
	}
	if env.TenantID == (uuid.UUID{}) {
		return ErrEnvelope("TenantID is zero")
	}
	if env.CorrelationID == (uuid.UUID{}) {
		return ErrEnvelope("CorrelationID is zero")
	}
	if env.Actor.PrincipalID == "" {
		return ErrEnvelope("Actor.PrincipalID is empty")
	}
	if env.OccurredAt.IsZero() {
		return ErrEnvelope("OccurredAt is zero")
	}
	return nil
}

// ErrEnvelope wraps envelope-validation errors so callers can distinguish
// them from command-specific validation failures.
type ErrEnvelope string

func (e ErrEnvelope) Error() string { return "envelope: " + string(e) }

// aggregateState is the current folded state of an investigation, computed from
// its event stream. The Handler folds the stream in-transaction and hands this
// to applyCommand so transition legality is checked against authoritative state
// (not a projection that could lag or be mid-rebuild).
type aggregateState struct {
	Seq           int64                      // sequence number of the last event (0 if none)
	Exists        bool                       // an investigation.created has been seen
	TenantID      uuid.UUID                  // tenant stamped at creation; immutable thereafter
	Status        string                     // current lifecycle status
	ConclusionRef string                     // set while concluded, cleared on reopen
	Actions       map[uuid.UUID]actionState  // per-x-action folded state (C.1)
	Hypotheses    map[string]hypothesisState // per-x-hypothesis folded state, keyed by STIX id (D.2)
	Predictions   map[string]predictionState // per-x-prediction folded state, keyed by STIX id (D.2)

	// Interpretation bookkeeping for supersession + the pin/verdict folds
	// (01 §Pinned evidence / §Verdict): every recorded interpretation's type
	// (supersede targets must exist and be free-standing), the active-pin set,
	// the superseded set, and the ordered verdict acts.
	Interpretations   map[uuid.UUID]string // interpretation id → type
	SupersededInterps map[uuid.UUID]bool
	Pins              map[uuid.UUID]bool // evidence-pin id → still active
	Verdicts          []verdictEntry     // in fold order; last non-superseded wins
}

// foldState replays an event stream into the current aggregateState. Only
// lifecycle-bearing events move the investigation state machine; membership
// events advance Seq but leave status unchanged. Action events fold into the
// per-action state map (foldActionEvent); interpretation events carrying
// reasoning-node content fold into the hypothesis/prediction maps
// (foldReasoningEvent) so node transition legality is checked against
// authoritative state.
func foldState(events []Event) (aggregateState, error) {
	s := aggregateState{
		Actions:           make(map[uuid.UUID]actionState),
		Hypotheses:        make(map[string]hypothesisState),
		Predictions:       make(map[string]predictionState),
		Interpretations:   make(map[uuid.UUID]string),
		SupersededInterps: make(map[uuid.UUID]bool),
		Pins:              make(map[uuid.UUID]bool),
	}
	for _, e := range events {
		s.Seq = e.SequenceNo
		switch e.Type {
		case EventTypeCreated:
			s.Exists = true
			s.TenantID = e.TenantID
			s.Status = StatusDraft
		case EventTypeStatusChanged:
			var p InvestigationStatusChanged
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return aggregateState{}, fmt.Errorf("fold status_changed seq %d: %w", e.SequenceNo, err)
			}
			s.Status = p.To
		case EventTypeConcluded:
			var p InvestigationConcluded
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return aggregateState{}, fmt.Errorf("fold concluded seq %d: %w", e.SequenceNo, err)
			}
			s.Status = StatusConcluded
			s.ConclusionRef = p.ReportRef
		case EventTypeReopened:
			s.Status = StatusActive
			s.ConclusionRef = ""
		case EventTypeArchived:
			s.Status = StatusArchived
		case EventTypeActionRequested, EventTypeActionApproved, EventTypeActionRejected,
			EventTypeActionExpired, EventTypeActionDispatched, EventTypeActionResulted,
			EventTypeActionReversed, EventTypeActionPolicyEvaluated:
			// PolicyEvaluated is audit-only (no status change); foldActionEvent
			// ignores it. The rest drive the per-action state machine.
			if err := foldActionEvent(s.Actions, e); err != nil {
				return aggregateState{}, err
			}
		case EventTypeInterpretationRecorded:
			// Most interpretation events carry no node content (lifecycle,
			// action-*, free-standing reasoning) — foldReasoningEvent no-ops on
			// those; hypothesis/prediction content drives the node state maps.
			var rec InterpretationRecorded
			if err := json.Unmarshal(e.Payload, &rec); err != nil {
				return aggregateState{}, fmt.Errorf("fold interpretation.recorded seq %d: %w", e.SequenceNo, err)
			}
			foldReasoningEvent(&s, rec)
			s.Interpretations[rec.InterpretationID] = rec.InterpretationType
			switch rec.InterpretationType {
			case InterpretationEvidencePin:
				s.Pins[rec.InterpretationID] = true
			case InterpretationVerdict:
				if rec.Verdict != nil {
					s.Verdicts = append(s.Verdicts, verdictEntry{
						InterpID: rec.InterpretationID, Disposition: rec.Verdict.Disposition,
					})
				}
			}
		case EventTypeInterpretationSuperseded:
			var p InterpretationSupersededPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return aggregateState{}, fmt.Errorf("fold interpretation.superseded seq %d: %w", e.SequenceNo, err)
			}
			foldSupersession(&s, p)
		}
	}
	return s, nil
}

// EventTypeCreated is the type tag for events that record an investigation
// being created.
const EventTypeCreated = "investigation.created"

// applyCommand translates (Envelope, Command, current state) into the events to
// persist + apply. It is the pure-function layer — no database, no transaction;
// the Handler folds the state, wraps the transaction, and projects.
//
// Two cross-cutting guards run before dispatch: every command except
// CreateInvestigation requires the aggregate to exist, and an archived
// investigation is terminal — it accepts no further events of any kind
// (01-domain-model.md §Extension 2).
func applyCommand(env Envelope, cmd Command, state aggregateState) ([]Event, error) {
	if err := cmd.Validate(env); err != nil {
		return nil, err
	}

	// AI write-protection (04 §5.6): AI_DELEGATED commands are validated against
	// an ALLOWLIST — spec wording, deliberately, so any future command (C.4's
	// dispatch/result/reversal, and everything after) is AI-denied by default
	// until explicitly admitted. Enforced here at the aggregate boundary — the
	// single write path — so it cannot be bypassed by an alternate code path.
	// NOTE for the HTTP layer: Actor.Kind must be derived from the JWT's
	// delegate_kind claim, never from the request body, or this guard is
	// caller-spoofable.
	if env.Actor.IsAIDelegated() && !aiAllowed(cmd) {
		return nil, fmt.Errorf("%s rejected: %w", cmd.Kind(), ErrAIDenied)
	}

	// System-only guard: dispatch/result/expiry are lifecycle transitions the
	// Temporal workflows/timers emit — never a human or AI directly. Requiring
	// a SYSTEM actor keeps the workflow the single emitter and stops a spoofed
	// command from forging a dispatch or an outcome.
	if systemOnly(cmd) && env.Actor.Kind != ActorSystem {
		return nil, fmt.Errorf("%s rejected: system-emitted command requires a SYSTEM actor, got %q", cmd.Kind(), env.Actor.Kind)
	}

	if _, isCreate := cmd.(CreateInvestigation); !isCreate {
		if !state.Exists {
			return nil, fmt.Errorf("%s on non-existent investigation %s: %w", cmd.Kind(), env.AggregateID, ErrNotFound)
		}
		// An aggregate belongs to exactly one tenant, stamped at creation
		// (01-domain-model.md §5). A command arriving under a different tenant
		// must not stamp foreign tenant_ids onto later events of the stream.
		if env.TenantID != state.TenantID {
			return nil, fmt.Errorf("%s rejected: envelope tenant %s does not match investigation tenant %s", cmd.Kind(), env.TenantID, state.TenantID)
		}
		if state.Status == StatusArchived {
			return nil, fmt.Errorf("%s rejected: investigation %s is archived (terminal)", cmd.Kind(), env.AggregateID)
		}
	}

	switch c := cmd.(type) {
	case CreateInvestigation:
		if state.Exists {
			return nil, fmt.Errorf("CreateInvestigation on existing aggregate %s (seq=%d)", env.AggregateID, state.Seq)
		}
		payload, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		return []Event{{
			AggregateID:   env.AggregateID,
			SequenceNo:    state.Seq + 1,
			TenantID:      env.TenantID,
			Type:          EventTypeCreated,
			Version:       schemaVersion,
			Payload:       payload,
			Actor:         env.Actor,
			OccurredAt:    env.OccurredAt,
			CorrelationID: env.CorrelationID,
		}}, nil
	case ActivateInvestigation:
		return statusTransition(env, state, StatusDraft, StatusActive, c.Reason)
	case PauseInvestigation:
		return statusTransition(env, state, StatusActive, StatusPaused, c.Reason)
	case ResumeInvestigation:
		return statusTransition(env, state, StatusPaused, StatusActive, c.Reason)
	case ConcludeInvestigation:
		return concludeEvents(env, state, c)
	case ReopenInvestigation:
		return reopenEvents(env, state, c)
	case ArchiveInvestigation:
		return archiveEvents(env, state, c)
	case AddMember:
		return membershipEvent(env, state, EventTypeMemberAdded, MemberAdded(c))
	case RemoveMember:
		return membershipEvent(env, state, EventTypeMemberRemoved, MemberRemoved(c))
	case AttachEvidence:
		return membershipEvent(env, state, EventTypeEvidenceAttached, EvidenceAttached(c))
	case RequestAction:
		return applyRequestAction(env, state, c)
	case ApproveAction:
		return applyApproveAction(env, state, c)
	case RejectAction:
		return applyRejectAction(env, state, c)
	case ExpireAction:
		return applyExpireAction(env, state, c)
	case DispatchAction:
		return applyDispatchAction(env, state, c)
	case ResultAction:
		return applyResultAction(env, state, c)
	case ReverseAction:
		return applyReverseAction(env, state, c)
	case RecordReversalAttempt:
		return applyReversalAttempt(env, state, c)
	case RecordInterpretation:
		return applyRecordInterpretation(env, state, c)
	case SupersedeInterpretation:
		return applySupersedeInterpretation(env, state, c)
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Kind())
	}
}

// aiAllowed is the AI_DELEGATED command allowlist (04 §5.6). It admits exactly
// the T1-annotate tier (04 §1: hypotheses, membership, evidence, lifecycle
// DRAFT↔ACTIVE↔PAUSED — "the AI agent operates freely here"), RecordInterpretation
// (the AI is the legal author of x-interpretation — reasoning is annotate-tier,
// 03 §1), plus RequestAction (the AI may PROPOSE a T2/T3 action; 08 §2).
// Everything else — approve / reject / expire, conclude / reopen / archive, and
// any future command — defaults to denied. Approving, and concluding an
// investigation, are human acts.
func aiAllowed(cmd Command) bool {
	switch cmd.(type) {
	case CreateInvestigation,
		ActivateInvestigation, PauseInvestigation, ResumeInvestigation,
		AddMember, RemoveMember, AttachEvidence,
		RecordInterpretation, SupersedeInterpretation,
		RequestAction:
		// RecordInterpretation admission does NOT make every act AI-legal: the
		// per-act guards inside it still apply (human-only hypothesis ack; the
		// AI-verdict dial's default-deny). SupersedeInterpretation is reasoning
		// correction — annotate-tier, same footing as recording.
		return true
	default:
		return false
	}
}
