DROP INDEX IF EXISTS stix_edges_type_idx;
DROP INDEX IF EXISTS stix_edges_tenant_target_idx;
DROP INDEX IF EXISTS stix_edges_tenant_source_idx;
DROP TABLE IF EXISTS stix_edges;

DROP INDEX IF EXISTS stix_objects_modified_idx;
DROP INDEX IF EXISTS stix_objects_tenant_type_idx;
DROP TABLE IF EXISTS stix_objects;
