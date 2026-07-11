package server

import (
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/module"
)

// newEnvelope stamps the standard command envelope every /api write handler
// uses: fresh correlation id, the convention timestamp, and the single OSS
// tenant. TenantID is the one line that changes when the paid tenancy module
// is wired in (module.TenancyModule.ResolveTenant, resolved from the JWT /
// claim routing) — keeping it here means it changes in exactly one place.
func newEnvelope(aggregateID uuid.UUID, actor aggregate.Actor, occurredAt time.Time) aggregate.Envelope {
	return aggregate.Envelope{
		AggregateID:   aggregateID,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		Actor:         actor,
		OccurredAt:    occurredAt,
	}
}

// commandNow returns the envelope timestamp convention: UTC, truncated to
// Postgres's microsecond precision so persisted values round-trip equal.
func commandNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
