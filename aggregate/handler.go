package aggregate

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracer emits the aggregate's spans. Cached at package init; the global
// tracer delegates to whatever provider telemetry.Setup installs at startup,
// so spans are inert (but harmless) if Setup never runs — e.g. in unit tests.
var tracer = otel.Tracer("reckon/aggregate")

// Handler orchestrates command-to-events translation, atomic event-append
// + projection-update inside a single Postgres transaction, and cold replay.
//
// The Handler owns the *sql.DB; commands flow through Handle.
type Handler struct {
	store      *Store
	projectors []Projector
}

// NewHandler constructs a Handler with the given store and projectors.
// Projectors apply in the order they are passed; ordering matters only if
// projections read from each other (none today).
func NewHandler(store *Store, projectors ...Projector) *Handler {
	return &Handler{store: store, projectors: projectors}
}

// Result is what Handle returns: the events that were persisted and the
// aggregate's new latest sequence number.
type Result struct {
	AggregateID   AggregateID
	AppliedEvents []Event
	NewSequenceNo int64
}

// Handle executes one command:
//
//  1. BEGIN TX
//  2. Read the aggregate's current sequence number
//  3. applyCommand → list of events to persist
//  4. For each event: AppendEventTx + every Projector's Apply
//  5. COMMIT
//
// If anything fails, the transaction rolls back; nothing is persisted.
// Returns ErrConcurrent if another writer beat us to the aggregate
// (callers should reload, re-execute, and retry).
func (h *Handler) Handle(ctx context.Context, env Envelope, cmd Command) (res Result, err error) {
	ctx, span := tracer.Start(ctx, "aggregate.Handle", trace.WithAttributes(
		attribute.String("command.type", fmt.Sprintf("%T", cmd)),
		attribute.String("aggregate.id", fmt.Sprintf("%v", env.AggregateID)),
	))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	tx, err := h.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Fold the stream in-transaction so transition legality is checked against
	// authoritative state under the same snapshot as the subsequent append.
	stream, err := h.store.LoadStreamTx(ctx, tx, env.AggregateID)
	if err != nil {
		return Result{}, err
	}
	state, err := foldState(stream)
	if err != nil {
		return Result{}, err
	}

	events, err := applyCommand(env, cmd, state)
	if err != nil {
		return Result{}, err
	}

	for i := range events {
		// Mint the infrastructure identity here — not in applyCommand — so the
		// pure layer stays free of write-time concerns and the caller's
		// Result.AppliedEvents carries the persisted identity.
		if events[i].EventID == (uuid.UUID{}) {
			events[i].EventID = uuid.Must(uuid.NewV7())
		}
		if events[i].Version == 0 {
			events[i].Version = schemaVersion
		}
		if err := h.store.AppendEventTx(ctx, tx, events[i]); err != nil {
			return Result{}, err
		}
		// One span per event covers the projection update — the third layer of
		// the A.8 trace (HTTP → aggregate.Handle → aggregate.project).
		_, pspan := tracer.Start(ctx, "aggregate.project",
			trace.WithAttributes(attribute.String("event.type", events[i].Type)))
		for _, p := range h.projectors {
			if perr := p.Apply(ctx, tx, events[i]); perr != nil {
				pspan.RecordError(perr)
				pspan.SetStatus(codes.Error, perr.Error())
				pspan.End()
				return Result{}, fmt.Errorf("projector %s: %w", p.Name(), perr)
			}
		}
		pspan.End()
	}

	if err := tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("commit: %w", err)
	}
	committed = true

	newSeq := state.Seq
	if n := len(events); n > 0 {
		newSeq = events[n-1].SequenceNo
	}
	return Result{
		AggregateID:   env.AggregateID,
		AppliedEvents: events,
		NewSequenceNo: newSeq,
	}, nil
}

// Replay rebuilds every projection from the event stream. Used after a
// projector bug fix or schema change. Performs Reset + re-apply inside a
// single transaction so partial replays can't leave a projection visibly
// half-rebuilt to readers (READ COMMITTED is enough — readers see the
// pre-replay snapshot until commit).
//
// Cost is O(events × projectors); for OSS solo this is fine. v1+ may move
// to per-projector replay with checkpoint tracking.
func (h *Handler) Replay(ctx context.Context) error {
	tx, err := h.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, p := range h.projectors {
		if err := p.Reset(ctx, tx); err != nil {
			return fmt.Errorf("reset %s: %w", p.Name(), err)
		}
	}

	// Stream every event in canonical replay order: (aggregate_id, sequence_no).
	// Deliberately NOT occurred_at — that is caller-supplied wall-clock time and
	// nothing enforces per-aggregate monotonicity (clock step-back, second
	// writer), so time-first ordering could apply one aggregate's events out of
	// sequence and silently corrupt projections. Both projections are keyed
	// per-aggregate, so cross-aggregate interleaving order is immaterial;
	// sequence_no is the only ordering the aggregate guarantees. Same query the
	// Store exposes via LoadAll, but run inside the replay tx for snapshot
	// consistency with the projection writes.
	rows, err := tx.QueryContext(ctx, `
		SELECT aggregate_id, sequence_no, tenant_id, event_type, payload, actor, occurred_at, correlation_id, event_id, event_version, recorded_at, causation_id
		FROM events
		ORDER BY aggregate_id, sequence_no
	`)
	if err != nil {
		return fmt.Errorf("query events for replay: %w", err)
	}
	defer rows.Close()

	events, err := scanEvents(rows)
	if err != nil {
		return err
	}

	for _, evt := range events {
		for _, p := range h.projectors {
			if err := p.Apply(ctx, tx, evt); err != nil {
				return fmt.Errorf("replay %s on event %d: %w", p.Name(), evt.SequenceNo, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replay: %w", err)
	}
	committed = true
	return nil
}

// DB returns the underlying *sql.DB. Useful for callers that need to read
// projection tables directly without going through the Handler.
func (h *Handler) DB() *sql.DB { return h.store.db }
