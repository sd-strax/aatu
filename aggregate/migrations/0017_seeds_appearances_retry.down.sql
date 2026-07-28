DROP TABLE IF EXISTS ref_appearances;

ALTER TABLE action_current DROP COLUMN IF EXISTS retry_of;

ALTER TABLE investigation_current
    DROP COLUMN IF EXISTS seed,
    DROP COLUMN IF EXISTS seed_type,
    DROP COLUMN IF EXISTS seed_summary;
