-- 0017: seeds on the projection, cross-investigation ref appearances, and
-- retry lineage.
--
-- seed_* (01 §Extension 1): the investigation's root, denormalized for the
-- triage queue ("what is this case about?"). seed holds the full shape;
-- seed_type/seed_summary are the indexed/displayed columns.
--
-- ref_appearances (design/ui binding §6.1 — "appears in N other
-- investigations"): one row per (ref, investigation), folded from every
-- interpretation's citations, every action's targets, and entity seeds.
-- This is the memory join the entity popover reads; identity being
-- deterministic (03 §7) is what makes the ref a join key at all.
--
-- retry_of on action_current: lineage to the FAILED/EXPIRED action this one
-- replaces (a retry IS a new action — the dispatch ledger forbids re-use).

ALTER TABLE investigation_current
    ADD COLUMN IF NOT EXISTS seed JSONB,
    ADD COLUMN IF NOT EXISTS seed_type TEXT,
    ADD COLUMN IF NOT EXISTS seed_summary TEXT;

ALTER TABLE action_current
    ADD COLUMN IF NOT EXISTS retry_of UUID;

CREATE TABLE IF NOT EXISTS ref_appearances (
    ref          TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    tenant_id    UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    first_seen   TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen    TIMESTAMP WITH TIME ZONE NOT NULL,
    mentions     INT NOT NULL DEFAULT 1,
    PRIMARY KEY (ref, aggregate_id)
);

CREATE INDEX IF NOT EXISTS ref_appearances_aggregate_idx ON ref_appearances (aggregate_id);
