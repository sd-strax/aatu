-- 0001_events: investigation event store
--
-- Single append-only events table per design/02-persistence.md.
-- (aggregate_id, sequence_no) is the primary key — supports optimistic
-- concurrency: an INSERT with a stale sequence_no fails on conflict.
--
-- payload is JSONB so projection queries can index into event-shape-specific
-- fields without rigid columns. actor captures the human principal + AI
-- delegate per the architectural commitment in 01-domain-model.md.

CREATE TABLE IF NOT EXISTS events (
    aggregate_id  UUID NOT NULL,
    sequence_no   BIGINT NOT NULL,
    event_type    TEXT NOT NULL,
    payload       JSONB NOT NULL,
    actor         JSONB NOT NULL,
    occurred_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (aggregate_id, sequence_no)
);

-- Indexes:
-- - occurred_at for time-range scans on the full event stream (audit,
--   replay, post-conclusion pipeline)
-- - event_type for selective replay during projection rebuilds and for
--   ad-hoc analysis by event-shape
CREATE INDEX IF NOT EXISTS events_occurred_at_idx ON events (occurred_at);
CREATE INDEX IF NOT EXISTS events_event_type_idx ON events (event_type);
