package aggregate

import (
	"context"
	"database/sql"
)

// Projector applies events to derived state (a "projection" / "read model").
//
// Apply runs inside the same transaction as the event-append, so the
// event-store and the projection table can never disagree about whether
// an event was applied.
//
// Reset wipes the projection's stored state — used by Replay before
// re-applying every event from scratch. Implementations typically TRUNCATE
// their backing tables.
type Projector interface {
	// Name is a stable identifier for logging.
	Name() string
	// Apply updates derived state for the given event. Runs inside tx.
	Apply(ctx context.Context, tx *sql.Tx, evt Event) error
	// Reset wipes the projection's stored state. Runs inside tx.
	Reset(ctx context.Context, tx *sql.Tx) error
}
