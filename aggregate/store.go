package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ErrConcurrent is returned when an event-append loses an optimistic
// concurrency race — another writer advanced the same aggregate past the
// expected sequence number. Callers should reload, re-execute the command,
// and retry.
var ErrConcurrent = errors.New("optimistic concurrency: aggregate moved")

// Store is the event-store interface to reckon_main.events. The Store does
// not own a transaction — callers (typically the Handler) pass one in so
// the event-append and projection-update share atomicity.
type Store struct {
	db *sql.DB
}

// NewStore wraps the given *sql.DB.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// AppendEventTx inserts the given Event inside the supplied transaction.
// Returns ErrConcurrent if (aggregate_id, sequence_no) is already taken.
//
// EventID is minted here (UUIDv7) when the caller left it zero — it is an
// infrastructure identity, assigned at write time, never produced by
// applyCommand. Version defaults to schemaVersion when zero for the same
// reason raw-store callers (tests) shouldn't have to know the current schema
// version. recorded_at is stamped by the database (DEFAULT NOW()), not
// carried in.
func (s *Store) AppendEventTx(ctx context.Context, tx *sql.Tx, evt Event) error {
	actorJSON, err := json.Marshal(evt.Actor)
	if err != nil {
		return fmt.Errorf("marshal actor: %w", err)
	}
	if evt.EventID == (uuid.UUID{}) {
		evt.EventID = uuid.Must(uuid.NewV7())
	}
	if evt.Version == 0 {
		evt.Version = schemaVersion
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO events (aggregate_id, sequence_no, tenant_id, event_type, payload, actor, occurred_at, correlation_id, event_id, event_version, causation_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`,
		evt.AggregateID, evt.SequenceNo, evt.TenantID, evt.Type, []byte(evt.Payload), actorJSON, evt.OccurredAt, evt.CorrelationID, evt.EventID, evt.Version, evt.CausationID,
	)
	if err != nil {
		if isConcurrencyViolation(err) {
			return ErrConcurrent
		}
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// LoadStream returns all events for the given aggregate in sequence order.
// Used by Replay and by callers wanting to materialize aggregate state.
func (s *Store) LoadStream(ctx context.Context, aggID AggregateID) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT aggregate_id, sequence_no, tenant_id, event_type, payload, actor, occurred_at, correlation_id, event_id, event_version, recorded_at, causation_id
		FROM events
		WHERE aggregate_id = $1
		ORDER BY sequence_no
	`, aggID)
	if err != nil {
		return nil, fmt.Errorf("query stream: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

// LoadStreamTx returns all events for the given aggregate in sequence order,
// reading inside the supplied transaction. The Handler uses it to fold current
// aggregate state (status, conclusion) for command validation under the same
// snapshot as the subsequent append.
func (s *Store) LoadStreamTx(ctx context.Context, tx *sql.Tx, aggID AggregateID) ([]Event, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT aggregate_id, sequence_no, tenant_id, event_type, payload, actor, occurred_at, correlation_id, event_id, event_version, recorded_at, causation_id
		FROM events
		WHERE aggregate_id = $1
		ORDER BY sequence_no
	`, aggID)
	if err != nil {
		return nil, fmt.Errorf("query stream (tx): %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

// LoadAll returns every event across every aggregate, ordered by
// (aggregate_id, sequence_no) — the only ordering the aggregate guarantees.
// occurred_at is caller-supplied wall-clock time with no per-aggregate
// monotonicity guarantee, so it must never drive replay order (see
// Handler.Replay). Used by Replay to rebuild projections from cold.
func (s *Store) LoadAll(ctx context.Context) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT aggregate_id, sequence_no, tenant_id, event_type, payload, actor, occurred_at, correlation_id, event_id, event_version, recorded_at, causation_id
		FROM events
		ORDER BY aggregate_id, sequence_no
	`)
	if err != nil {
		return nil, fmt.Errorf("query all events: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var (
			e            Event
			payloadBytes []byte
			actorBytes   []byte
		)
		if err := rows.Scan(&e.AggregateID, &e.SequenceNo, &e.TenantID, &e.Type, &payloadBytes, &actorBytes, &e.OccurredAt, &e.CorrelationID, &e.EventID, &e.Version, &e.RecordedAt, &e.CausationID); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.Payload = json.RawMessage(payloadBytes)
		if err := json.Unmarshal(actorBytes, &e.Actor); err != nil {
			return nil, fmt.Errorf("unmarshal actor for seq %d: %w", e.SequenceNo, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// isConcurrencyViolation reports whether err is a unique violation on the
// events primary key (aggregate_id, sequence_no) — the optimistic-concurrency
// guard. The constraint name is matched explicitly so violations of other
// unique constraints on the table (events_event_id_key) surface as plain
// errors rather than masquerading as ErrConcurrent.
func isConcurrencyViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		// 23505 = unique_violation per the SQL standard
		return pqErr.Code == "23505" && pqErr.Constraint == "events_pkey"
	}
	return false
}
