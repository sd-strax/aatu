-- 0006_event_correlation_id: group an event with the others a single command
-- produced.
--
-- A command may append more than one event in its transaction — a lifecycle
-- transition writes both the lifecycle event and its paired
-- InterpretationRecorded (02-persistence.md §3). They share a correlation_id so
-- the reasoning trail can be reassembled and the pairing audited.
--
-- Added NOT NULL via a transient zero default so the change is safe whether or
-- not the table already holds rows; the default is then dropped, since every
-- write supplies a real correlation_id from the command envelope.

ALTER TABLE events ADD COLUMN correlation_id UUID NOT NULL
    DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE events ALTER COLUMN correlation_id DROP DEFAULT;

CREATE INDEX IF NOT EXISTS events_correlation_id_idx ON events (correlation_id);
