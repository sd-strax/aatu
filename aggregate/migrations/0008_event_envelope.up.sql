-- 0008_event_envelope: catch the events table up to the full event envelope
-- defined in design/02-persistence.md §3.
--
-- - event_id: stable per-event global identifier. The natural key stays
--   (aggregate_id, sequence_no) — it is the optimistic-concurrency guard — so
--   event_id is UNIQUE, not the PK; it exists so side stores (ai_tool_calls)
--   and cross-store provenance can reference one event without carrying the
--   composite key. Writers mint UUIDv7 (time-ordered); pre-existing rows are
--   backfilled with random UUIDs.
--
-- - event_version: payload schema version per event type, so payloads can be
--   upcast when their shape evolves (02-persistence.md §5). Every event
--   written before this migration is version 1 (no shape has changed yet).
--   Backfilled via a transient default, then dropped — writers must supply it.
--
-- - recorded_at: DB-stamped write time, distinct from the caller-supplied
--   business time occurred_at. Kept as a live DEFAULT NOW(): stamping at
--   insert is the point of the column.
--
-- - causation_id: the event that caused this one, for event-chain provenance.
--   NULL for command-initiated events (all events today); populated when
--   system-emitted event chains land (Temporal workflows, Phase C+).

ALTER TABLE events ADD COLUMN event_id UUID;
UPDATE events SET event_id = gen_random_uuid() WHERE event_id IS NULL;
ALTER TABLE events ALTER COLUMN event_id SET NOT NULL;
ALTER TABLE events ADD CONSTRAINT events_event_id_key UNIQUE (event_id);

ALTER TABLE events ADD COLUMN event_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE events ALTER COLUMN event_version DROP DEFAULT;

ALTER TABLE events ADD COLUMN recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();

ALTER TABLE events ADD COLUMN causation_id UUID;
