package aggregate

// Investigation lifecycle states — the "Lifecycle" extension state machine
// (design/01-domain-model.md §Extension 2). Stored lowercase in the
// investigation_current projection; the spec writes them uppercase in prose.
//
// The machine:
//
//	draft ──activate──▶ active ──conclude──▶ concluded ──archive──▶ archived
//	                     ▲   │                   │
//	               resume│   │pause         reopen│ (clears conclusion_ref)
//	                     │   ▼                   ▼
//	                    paused                 active
//
// draft is the entry state: an investigation that can be reasoned over (the
// interpretation layer — hypotheses, notes, evidence) and can even accept an
// external-action REQUEST, but is not yet cleared to *act* on the world.
// Activation is implicit at the action boundary (01-domain-model.md §Extension
// 2, "invisible activate"): the first APPROVAL of a draft's action transitions
// draft→active in the same transaction, and auto-approve is suppressed until
// then so that first action always gets a human. archived is terminal — the
// aggregate accepts no further events.
const (
	StatusDraft     = "draft"
	StatusActive    = "active"
	StatusPaused    = "paused"
	StatusConcluded = "concluded"
	StatusArchived  = "archived"
)
