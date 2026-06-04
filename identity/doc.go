// Package identity holds the deterministic UUIDv5 identity resolver and
// per-tenant namespace UUID logic. Same entity → same id across producers
// and investigations within a tenant; aliasing is an explicit edge, never
// a destructive merge. Lands in Phase B alongside the capability layer.
// See design/01-domain-model.md §3 and §5.
package identity
