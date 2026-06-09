-- 0003_stix_objects: STIX 2.1 object store
--
-- The interpretation layer per the two-layer graph architectural commitment
-- (01-domain-model.md). STIX objects are stored with their canonical
-- deterministic UUIDv5 id and the full STIX JSON payload.
--
-- type is denormalized for indexed queries (e.g., "all x-host objects for
-- this investigation"). Inline JSON access works too but is slower for
-- type-filtered scans.
--
-- tenant_id partitions the interpretation layer per the always-present tenant
-- primitive (05-component-architecture.md §3). The id is already globally
-- unique by the per-tenant namespace UUID rule (01-domain-model.md §3), so
-- tenant_id is the defense-in-depth filter the paid RLS policies key on.

CREATE TABLE IF NOT EXISTS stix_objects (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    type          TEXT NOT NULL,
    spec_version  TEXT NOT NULL DEFAULT '2.1',
    payload       JSONB NOT NULL,
    created       TIMESTAMP WITH TIME ZONE NOT NULL,
    modified      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS stix_objects_tenant_type_idx ON stix_objects (tenant_id, type);
CREATE INDEX IF NOT EXISTS stix_objects_modified_idx ON stix_objects (modified);

-- Typed edges between STIX objects (relationship objects + interpretation
-- linkage). Per 01-domain-model.md the joins between telemetry and
-- interpretation layers are typed edges, never embedded references. The table
-- is named stix_edges to match the canonical name in 02-persistence.md §2.2 and
-- 05-component-architecture.md — it holds more than standard STIX relationship
-- types (member-of, x-supports, x-refutes, aliases, ...). tenant_id is the
-- always-present partition key; the rest of the column-level schema is a
-- placeholder — the authoritative edge shape (subject/predicate/object) lands
-- with STIX CRUD in Phase B (the tenant-leading indexes already match
-- 02-persistence.md §2.2).
CREATE TABLE IF NOT EXISTS stix_edges (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    source_ref    UUID NOT NULL,
    target_ref    UUID NOT NULL,
    relationship_type TEXT NOT NULL,
    payload       JSONB NOT NULL,
    created       TIMESTAMP WITH TIME ZONE NOT NULL,
    modified      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS stix_edges_tenant_source_idx ON stix_edges (tenant_id, source_ref);
CREATE INDEX IF NOT EXISTS stix_edges_tenant_target_idx ON stix_edges (tenant_id, target_ref);
CREATE INDEX IF NOT EXISTS stix_edges_type_idx ON stix_edges (relationship_type);
