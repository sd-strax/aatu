-- 0002_stix_objects: STIX 2.1 object store
--
-- The interpretation layer per the two-layer graph architectural commitment
-- (01-domain-model.md). STIX objects are stored with their canonical
-- deterministic UUIDv5 id and the full STIX JSON payload.
--
-- type is denormalized for indexed queries (e.g., "all x-host objects for
-- this investigation"). Inline JSON access works too but is slower for
-- type-filtered scans.

CREATE TABLE IF NOT EXISTS stix_objects (
    id            UUID PRIMARY KEY,
    type          TEXT NOT NULL,
    spec_version  TEXT NOT NULL DEFAULT '2.1',
    payload       JSONB NOT NULL,
    created       TIMESTAMP WITH TIME ZONE NOT NULL,
    modified      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS stix_objects_type_idx ON stix_objects (type);
CREATE INDEX IF NOT EXISTS stix_objects_modified_idx ON stix_objects (modified);

-- Typed edges between STIX objects (relationship objects + interpretation
-- linkage). Per 01-domain-model.md the joins between telemetry and
-- interpretation layers are typed edges, never embedded references.
CREATE TABLE IF NOT EXISTS stix_relationships (
    id            UUID PRIMARY KEY,
    source_ref    UUID NOT NULL,
    target_ref    UUID NOT NULL,
    relationship_type TEXT NOT NULL,
    payload       JSONB NOT NULL,
    created       TIMESTAMP WITH TIME ZONE NOT NULL,
    modified      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS stix_relationships_source_idx ON stix_relationships (source_ref);
CREATE INDEX IF NOT EXISTS stix_relationships_target_idx ON stix_relationships (target_ref);
CREATE INDEX IF NOT EXISTS stix_relationships_type_idx ON stix_relationships (relationship_type);
