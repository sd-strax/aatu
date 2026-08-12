// Package substrate is the memory substrate — a consumer-neutral storage and
// retrieval component for institutional memory (knowledge/design/00-substrate.md).
// It stores prose entries with light structure across two corpus archetypes
// (CURATED procedures, DERIVED case knowledge), recalls the few most relevant
// with a rationale and an honest coverage verdict, bands document similarity,
// and can prove byte-for-byte what it returned at any point in the past
// (content-hash attestation, §3/§6).
//
// Boundary (§12, enforced by TestImportBoundary): this package and its
// subpackages import the standard library and third-party modules only —
// never the host repository's packages. Hosts consume it through the Store
// interface at their composition root. No host vocabulary appears here: the
// substrate sees an opaque namespace string and generic entries, not tenants,
// investigations, or STIX.
//
// It currently lives in-tree in its first consumer's repository as a staging
// choice; extraction to a standalone module is a move, not a redesign (§12).
package substrate
