DROP TABLE IF EXISTS evidence_pin_current;

ALTER TABLE investigation_current
    DROP COLUMN IF EXISTS verdict_disposition,
    DROP COLUMN IF EXISTS verdict_rationale,
    DROP COLUMN IF EXISTS verdict_at,
    DROP COLUMN IF EXISTS verdict_interpretation_id;
