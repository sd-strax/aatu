-- The memory substrate's own tables (00-substrate §2–§6). Consumer-neutral by
-- construction: namespace is an opaque partition key, corpus an opaque name.
-- Revisions are new rows (content rows are never mutated), which makes the
-- entries table itself the §6 snapshot store — any hash ever served resolves
-- to a live row or a purge tombstone.

CREATE TABLE substrate_entries (
    id             UUID PRIMARY KEY,
    namespace      TEXT NOT NULL CHECK (char_length(namespace) BETWEEN 1 AND 128),
    corpus         TEXT NOT NULL,

    -- Content (exactly the §3 hashed fields).
    title          TEXT NOT NULL,
    body           TEXT NOT NULL,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    meta           JSONB,
    advice         TEXT,

    status         TEXT NOT NULL CHECK (status IN ('DRAFT','IN_REVIEW','PUBLISHED','RETIRED')),
    revision       INT  NOT NULL CHECK (revision >= 1),
    -- SET NULL: purging a prior revision (compliance) breaks the chain link,
    -- not the purge — the tombstone still answers for the purged content.
    supersedes_ref UUID REFERENCES substrate_entries(id) ON DELETE SET NULL,
    version_label  TEXT,

    -- Curated governance.
    authored_by    TEXT,
    signed_off_by  TEXT[],

    -- Derived provenance (flattened; NULL producer = no stamp).
    prov_producer          TEXT,
    prov_producer_version  TEXT,
    prov_generator_model   TEXT,
    prov_source_ref        TEXT,

    content_hash   TEXT NOT NULL,
    hash_version   INT  NOT NULL,

    created        TIMESTAMPTZ NOT NULL,
    updated        TIMESTAMPTZ NOT NULL,
    published_at   TIMESTAMPTZ,
    retired_at     TIMESTAMPTZ,
    superseded_at  TIMESTAMPTZ,

    -- Keyword fallback backend (§10 v0): generated, so it can never drift
    -- from the content it indexes.
    fts tsvector GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || body)) STORED
);

CREATE INDEX substrate_entries_scope ON substrate_entries (namespace, corpus, status);
CREATE INDEX substrate_entries_hash  ON substrate_entries (namespace, content_hash);
CREATE INDEX substrate_entries_fts   ON substrate_entries USING GIN (fts);
CREATE INDEX substrate_entries_tags  ON substrate_entries USING GIN (tags);

-- One vector per (entry, model): embeddings are only comparable within a
-- model, so rows for old and new models coexist through a re-embed window
-- (§10) and recall joins on the active model only.
CREATE TABLE substrate_embeddings (
    entry_id   UUID NOT NULL REFERENCES substrate_entries(id) ON DELETE CASCADE,
    model      TEXT NOT NULL,
    dim        INT  NOT NULL CHECK (dim >= 1),
    vec        REAL[] NOT NULL,
    created    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (entry_id, model)
);

-- Purge tombstones (§4): purge removes content and its snapshots, leaving a
-- marker so Snapshot answers "content existed and was purged at T" rather
-- than pretending the hash was never served.
CREATE TABLE substrate_tombstones (
    namespace    TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    hash_version INT  NOT NULL,
    purged_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (namespace, content_hash)
);
