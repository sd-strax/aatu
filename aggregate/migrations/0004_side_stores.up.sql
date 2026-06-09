-- 0004_side_stores: AI tool-call log + transcript content-addressable store
--
-- Per design/05 §3.2 and design/02 — AI reasoning leaves a durable audit
-- trail in two side stores:
--
-- - ai_tool_calls: every tool dispatch the LLM made during an investigation,
--   with arguments, result hash, and provenance to the event that
--   triggered it. Lets compliance reviewers reconstruct "what data did
--   the AI see when it concluded X?".
--
-- - ai_transcripts: content-addressable store for raw LLM transcript bytes
--   (system prompt + user/assistant/tool messages). hash is the SHA-256
--   of the canonicalized body; event records that triggered the LLM call
--   reference this hash, not the body itself. Decouples bulky text from
--   the event store.
--
-- Both side stores carry tenant_id and gain per-tenant scoping when the paid
-- tenancy module is on (05-component-architecture.md §4). For ai_transcripts
-- the partition is part of the primary key — (tenant_id, hash) — so the
-- content-addressable property holds within a tenant while keeping tenants
-- isolated even when two produce byte-identical transcripts.

CREATE TABLE IF NOT EXISTS ai_tool_calls (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    investigation_id UUID NOT NULL,
    event_id        UUID,
    tool_name       TEXT NOT NULL,
    tool_args       JSONB NOT NULL,
    result_hash     TEXT,
    transcript_hash TEXT,
    occurred_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ai_tool_calls_tenant_investigation_idx ON ai_tool_calls (tenant_id, investigation_id);
CREATE INDEX IF NOT EXISTS ai_tool_calls_tool_name_idx ON ai_tool_calls (tool_name);
CREATE INDEX IF NOT EXISTS ai_tool_calls_occurred_at_idx ON ai_tool_calls (occurred_at);

CREATE TABLE IF NOT EXISTS ai_transcripts (
    tenant_id  UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    hash       TEXT NOT NULL,
    body       BYTEA NOT NULL,
    size_bytes INTEGER NOT NULL,
    stored_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hash)
);
