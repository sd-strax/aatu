-- 0002_events: investigation event store
--
-- Single append-only events table per design/02-persistence.md.
-- (aggregate_id, sequence_no) is the primary key — supports optimistic
-- concurrency: an INSERT with a stale sequence_no fails on conflict.
--
-- payload is JSONB so projection queries can index into event-shape-specific
-- fields without rigid columns. actor captures the human principal + AI
-- delegate per the architectural commitment in 01-domain-model.md.
--
-- tenant_id partitions the stream per the always-present tenant primitive
-- (05-component-architecture.md §3). It defaults to the single OSS tenant so
-- callers that do not yet resolve a tenant still write correct rows; the paid
-- tenancy module enforces RLS over this column without altering the schema
-- (§4). aggregate_id is a globally-unique UUID, so the natural key stays
-- (aggregate_id, sequence_no) — tenant_id leads only the audit index.

CREATE TABLE IF NOT EXISTS events (
    aggregate_id  UUID NOT NULL,
    sequence_no   BIGINT NOT NULL,
    tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    event_type    TEXT NOT NULL,
    payload       JSONB NOT NULL,
    actor         JSONB NOT NULL,
    occurred_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (aggregate_id, sequence_no)
);

-- Indexes:
-- - (tenant_id, occurred_at) for tenant-scoped time-range scans (audit,
--   recent-activity, post-conclusion pipeline)
-- - event_type for selective replay during projection rebuilds and for
--   ad-hoc analysis by event-shape
CREATE INDEX IF NOT EXISTS events_tenant_occurred_at_idx ON events (tenant_id, occurred_at);
CREATE INDEX IF NOT EXISTS events_event_type_idx ON events (event_type);
