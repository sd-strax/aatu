DROP INDEX IF EXISTS events_correlation_id_idx;
ALTER TABLE events DROP COLUMN IF EXISTS correlation_id;
