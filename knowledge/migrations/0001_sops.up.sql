-- 0001_sops: SOP repository
--
-- Per design/06-knowledge-service.md. SOPs are reckon's runbook content —
-- procedural guidance the LLM consults during reasoning.
--
-- governance_mode (configured at the deployment level) selects which
-- lifecycle a row goes through: 'lightweight' = write-it-use-it (status
-- transitions to 'published' immediately); 'gated' = draft → in_review
-- → published → retired with separate author/signer roles.
--
-- embedding is a TEXT placeholder for Phase G (D14: pgvector deferred).
-- When pgvector arrives, the column type becomes VECTOR(N) for the
-- chosen embedding dimension and existing TEXT rows are re-embedded.

CREATE TABLE IF NOT EXISTS sops (
    id           UUID PRIMARY KEY,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    tags         TEXT[] NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'published',
    author_id    UUID,
    signer_id    UUID,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,
    retired_at   TIMESTAMP WITH TIME ZONE,
    embedding    TEXT
);

CREATE INDEX IF NOT EXISTS sops_tags_idx ON sops USING GIN (tags);
CREATE INDEX IF NOT EXISTS sops_status_idx ON sops (status);
CREATE INDEX IF NOT EXISTS sops_updated_at_idx ON sops (updated_at);
