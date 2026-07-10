-- 0009_action_current: projection of the x-action lifecycle (C.1). One row per
-- x-action, keyed by action_id, materialized from the seven action.* events by
-- the ActionCurrentProjector inside the same transaction as the event-append.
--
-- x-actions are aggregate-internal (created by action.requested events, not in
-- the external STIX object store — 02-persistence.md §3), so this table is the
-- queryable view of "what actions exist and where they sit in the lifecycle."
-- A REQUESTED / PENDING_SECONDARY row is a pending approval (the review queue).

CREATE TABLE IF NOT EXISTS action_current (
    action_id            UUID PRIMARY KEY,
    aggregate_id         UUID NOT NULL,
    tenant_id            UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    action_type          TEXT NOT NULL,
    tier                 TEXT NOT NULL,
    status               TEXT NOT NULL,
    mode                 TEXT,               -- authorization mode; NULL until approved
    primary_approver_ref TEXT,               -- NULL until approved
    is_reversal          BOOLEAN NOT NULL DEFAULT FALSE,
    targets              JSONB NOT NULL,
    expires_at           TIMESTAMP WITH TIME ZONE,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_sequence  BIGINT NOT NULL
);

-- The review queue: pending actions for a tenant, and all actions for one
-- investigation.
CREATE INDEX IF NOT EXISTS action_current_tenant_status_idx ON action_current (tenant_id, status);
CREATE INDEX IF NOT EXISTS action_current_aggregate_idx ON action_current (aggregate_id);
CREATE INDEX IF NOT EXISTS action_current_expires_at_idx ON action_current (expires_at) WHERE expires_at IS NOT NULL;
