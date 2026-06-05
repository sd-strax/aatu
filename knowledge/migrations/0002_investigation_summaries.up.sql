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

CREATE TABLE IF NOT EXISTS investigation_summaries (
    investigation_id UUID PRIMARY KEY,
    title            TEXT NOT NULL,
    summary          TEXT NOT NULL,
    verdict          TEXT NOT NULL,
    tags             TEXT[] NOT NULL DEFAULT '{}',
    concluded_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    embedding        TEXT
);

CREATE INDEX IF NOT EXISTS summaries_concluded_at_idx ON investigation_summaries (concluded_at);
CREATE INDEX IF NOT EXISTS summaries_verdict_idx ON investigation_summaries (verdict);
CREATE INDEX IF NOT EXISTS summaries_tags_idx ON investigation_summaries USING GIN (tags);
