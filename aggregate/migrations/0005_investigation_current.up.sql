-- 0005_investigation_current: basic-state projection of the investigation
-- aggregate. One row per aggregate. Materialized from events by the
-- InvestigationCurrentProjector inside the same transaction as the
-- event-append.
--
-- tenant_id is carried from the projected event so the read model is
-- partitioned identically to the event stream; "list my investigations"
-- filters by (tenant_id, status).

CREATE TABLE IF NOT EXISTS investigation_current (
    aggregate_id        UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    title               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_sequence BIGINT NOT NULL,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS investigation_current_tenant_status_idx ON investigation_current (tenant_id, status);
CREATE INDEX IF NOT EXISTS investigation_current_updated_at_idx ON investigation_current (updated_at);
