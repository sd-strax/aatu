-- 0015: the verdict of record + the pinned-evidence projection (01 §Verdict /
-- §Pinned evidence; 02 §4).
--
-- Both are folds over interpretation events — no new event types exist
-- (derived facts stay derived). investigation_current grows the verdict fold
-- (latest non-superseded verdict act); evidence_pin_current materializes the
-- non-superseded evidence-pin acts for the workbench's pinned-evidence
-- surface. Rows projected before this migration read NULL/absent; a
-- Reset+replay backfills from the events.

ALTER TABLE investigation_current
    ADD COLUMN IF NOT EXISTS verdict_disposition TEXT,
    ADD COLUMN IF NOT EXISTS verdict_rationale TEXT,
    ADD COLUMN IF NOT EXISTS verdict_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS verdict_interpretation_id UUID;

CREATE TABLE IF NOT EXISTS evidence_pin_current (
    interpretation_id   UUID PRIMARY KEY,
    aggregate_id        UUID NOT NULL,
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    finding             TEXT NOT NULL,
    input_refs          JSONB NOT NULL,
    actor               JSONB NOT NULL,
    pinned_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    superseded          BOOLEAN NOT NULL DEFAULT FALSE,
    last_event_sequence BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_pin_current_aggregate_idx
    ON evidence_pin_current (aggregate_id);
