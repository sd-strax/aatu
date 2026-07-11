-- 0012_reasoning_nodes: investigation-scoped read models for the reasoning
-- nodes (x-hypothesis / x-prediction, 01-domain-model.md), Phase D.2.
--
-- The canonical STIX-shaped nodes live in stix_objects (written by the
-- ReasoningNodeProjector — the object store's first writer). These two tables
-- are the queryable projection over the same interpretation events, keyed by
-- full STIX id, same pattern as action_current: "open hypotheses for this
-- investigation" is an indexed scan, not a JSONB payload crawl.

CREATE TABLE IF NOT EXISTS hypothesis_current (
    id                  TEXT PRIMARY KEY,   -- full STIX id (x-hypothesis--<uuid>)
    aggregate_id        UUID NOT NULL,
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    statement           TEXT NOT NULL,
    status              TEXT NOT NULL,
    parent_ref          TEXT,               -- refinement chain
    rooted_at_ref       TEXT,               -- anchor entity (SCO id)
    labels              JSONB,              -- ATT&CK technique ids by convention
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_sequence BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS hypothesis_current_aggregate_idx ON hypothesis_current (aggregate_id);
CREATE INDEX IF NOT EXISTS hypothesis_current_tenant_status_idx ON hypothesis_current (tenant_id, status);

CREATE TABLE IF NOT EXISTS prediction_current (
    id                  TEXT PRIMARY KEY,   -- full STIX id (x-prediction--<uuid>)
    hypothesis_ref      TEXT NOT NULL,      -- the hypothesis it tests
    aggregate_id        UUID NOT NULL,
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    statement           TEXT NOT NULL,
    status              TEXT NOT NULL,
    test_result_refs    JSONB,              -- ObservedData / Sighting ids
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_sequence BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS prediction_current_aggregate_idx ON prediction_current (aggregate_id);
CREATE INDEX IF NOT EXISTS prediction_current_hypothesis_idx ON prediction_current (hypothesis_ref);
