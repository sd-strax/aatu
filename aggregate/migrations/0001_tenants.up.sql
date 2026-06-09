-- 0001_tenants: tenant registry
--
-- The tenant primitive is always present in the data model, in every
-- distribution (design/05-component-architecture.md §3, design/01-domain-model.md
-- §5 "Multi-tenant by construction"). OSS runs as a tenant of one; the paid
-- tenancy module adds NO tables and NO columns — it only activates RLS
-- enforcement and per-tenant routing over the schema defined here
-- (05-component-architecture.md §4). This table is therefore OSS-owned.
--
-- tenant_id is the partition key carried on every tenant-scoped row.
-- namespace_uuid is the immutable per-tenant UUIDv5 namespace used for
-- deterministic identity computation (01-domain-model.md §3); it is what makes
-- cross-tenant id collision structurally impossible, with RLS as
-- defense-in-depth rather than the sole isolation mechanism.
--
-- The single OSS tenant ('...0001') is seeded here so the data model is
-- self-consistent on first boot. A fresh namespace_uuid is generated at seed
-- time and is immutable thereafter — changing it would re-id every node in the
-- tenant. (`reckon init` may own richer tenant provisioning later; the row must
-- simply exist.)

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id      UUID PRIMARY KEY,
    name           TEXT NOT NULL,
    namespace_uuid UUID NOT NULL,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (tenant_id, name, namespace_uuid)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    gen_random_uuid()
)
ON CONFLICT (tenant_id) DO NOTHING;
