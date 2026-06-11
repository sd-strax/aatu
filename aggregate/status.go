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
// interpretation layer — hypotheses, notes, evidence) but is not yet cleared
// to dispatch external actions (04-action-authorization.md: the T1 tier allows
// draft→active→paused lifecycle changes freely, while draft investigations
// cannot request T2+ external actions). archived is terminal — the aggregate
// accepts no further events.
const (
	StatusDraft     = "draft"
	StatusActive    = "active"
	StatusPaused    = "paused"
	StatusConcluded = "concluded"
	StatusArchived  = "archived"
)
