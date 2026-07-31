-- 0018_comms_threads: the comms/external-work thread state (Phase F, design/ui
-- binding §4). OWNED BY THE comms PACKAGE — it lives in this migration set
-- because aggregate/migrations is the reckon_main schema set. Comms threads
-- are CRUD + thin history (the architectural commitment: only the
-- investigation aggregate is event-sourced): every outbound message is a
-- notify.* x-action whose audit record lives in the event log; this table
-- tracks the CONVERSATION state that follows — replies, follow-ups, closure.
CREATE TABLE IF NOT EXISTS comms_threads (
    thread_id        UUID PRIMARY KEY,
    aggregate_id     UUID NOT NULL,
    tenant_id        UUID NOT NULL,
    action_id        UUID NOT NULL,  -- the originating notify.* x-action
    action_type      TEXT NOT NULL,  -- notify.slack | notify.email
    target           TEXT NOT NULL,  -- channel / recipient
    subject          TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL,  -- awaiting_reply | replied | followed_up | closed
    follow_up_hours  INT  NOT NULL DEFAULT 0,
    follow_ups       INT  NOT NULL DEFAULT 0,
    unacked_reply    BOOLEAN NOT NULL DEFAULT FALSE,
    sent_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    next_followup_at TIMESTAMP WITH TIME ZONE,
    updated_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    trail            JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS comms_threads_aggregate_idx ON comms_threads (aggregate_id);
CREATE INDEX IF NOT EXISTS comms_threads_status_idx ON comms_threads (tenant_id, status);
