-- 0004_investigation_current: basic-state projection of the investigation
-- aggregate. One row per aggregate. Materialized from events by the
-- InvestigationCurrentProjector inside the same transaction as the
-- event-append.

CREATE TABLE IF NOT EXISTS investigation_current (
    aggregate_id        UUID PRIMARY KEY,
    title               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_sequence BIGINT NOT NULL,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS investigation_current_status_idx ON investigation_current (status);
CREATE INDEX IF NOT EXISTS investigation_current_updated_at_idx ON investigation_current (updated_at);
