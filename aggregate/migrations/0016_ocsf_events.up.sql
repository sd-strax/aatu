-- 0016: OCSF telemetry persistence (02 §2.3 — append-only insert; 03 §4.13
-- eager promotion at ingest).
--
-- Until now, capability invocations returned telemetry in the response only
-- ("Phase E.1 returns the envelope only") — every ocsf_event_ref the agent
-- cited pointed at a record that existed nowhere. This table is the ground
-- truth layer: raw OCSF payloads, immutable, retained exactly as the tool
-- returned them. The interpretation layer (stix_objects) references them;
-- evidence-open (design/ui 02 §2.8) reads them.
--
-- id is the telemetry-record PK (UUIDv7 minted at ingest), NOT a content
-- identity: re-invoking a verb re-ingests what the tool returned when asked —
-- append-only means the record of each asking is kept.

CREATE TABLE IF NOT EXISTS ocsf_events (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    class_uid   INT NOT NULL,
    class_name  TEXT NOT NULL,
    time        TIMESTAMP WITH TIME ZONE NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL,
    source_tool TEXT NOT NULL,
    payload     JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS ocsf_events_tenant_time_idx ON ocsf_events (tenant_id, time);
