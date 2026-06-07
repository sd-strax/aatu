-- 0002_investigation_summaries: concluded-investigation summary index
--
-- Per design/06-knowledge-service.md §summary corpus. Written by the
-- SummarizeForKnowledgeIndex workflow after an investigation concludes;
-- read by the LLM via recall_similar_investigations to surface analog
-- prior cases during reasoning.
--
-- verdict captures the conclusion shape (malicious / benign / inconclusive /
-- benign-fix-required) so the retrieval surface can filter by outcome.
--
-- embedding is a TEXT placeholder for Phase G (D14); same path as sops.
--
-- tenant_id partitions the summary corpus per the always-present tenant
-- primitive (05-component-architecture.md §3); recall_similar_investigations
-- only ever surfaces analogs from the caller's own tenant.

CREATE TABLE IF NOT EXISTS investigation_summaries (
    investigation_id UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    title            TEXT NOT NULL,
    summary          TEXT NOT NULL,
    verdict          TEXT NOT NULL,
    tags             TEXT[] NOT NULL DEFAULT '{}',
    concluded_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    embedding        TEXT
);

CREATE INDEX IF NOT EXISTS summaries_concluded_at_idx ON investigation_summaries (concluded_at);
CREATE INDEX IF NOT EXISTS summaries_tenant_verdict_idx ON investigation_summaries (tenant_id, verdict);
CREATE INDEX IF NOT EXISTS summaries_tags_idx ON investigation_summaries USING GIN (tags);
