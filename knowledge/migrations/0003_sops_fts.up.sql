-- 0003_sops_fts: v0 keyword retrieval (design/06 §4, §10) + the recommendation
-- token. No embeddings yet (Phase G, D14); recall_sops ranks with Postgres
-- full-text search over title+body until then.

-- The structured recommendation token (design/06 §2.1): metadata only — the
-- body stays unparsed prose — that feeds ctx.sop_guidance.recommendation in
-- Gate 2 (04 §4.2) once the agent loop wires retrieval into policy evaluation.
ALTER TABLE sops ADD COLUMN IF NOT EXISTS recommendation TEXT;

-- Full-text index over title+body so recall_sops ranks with ts_rank without a
-- sequential scan. English config is the v0 default; a config column can select
-- per-tenant language later.
CREATE INDEX IF NOT EXISTS sops_fts_idx
    ON sops USING GIN (to_tsvector('english', title || ' ' || body));
