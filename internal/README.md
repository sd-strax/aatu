# internal/

Truly internal helpers — utilities, shared infrastructure, and engine-private packages that are not part of the OSS-public commitment.

Go's `internal/` import-path convention restricts imports to the parent of `internal/` and its descendants; this is what enforces the "not part of the public API" guarantee.

## Status

Empty at Week 1. First inhabitants will land alongside the packages that need them — e.g., `internal/pgutil/` for Postgres helpers (Phase A.3), `internal/testutil/` for shared engine-test helpers, `internal/buildinfo/` for git SHA stamping.

`aatu-enterprise` may need to use some of these helpers in its own tests. The contract: anything `aatu-enterprise` legitimately depends on graduates out of `internal/` into a public package (or a designated `pkg/`); the rest stays restricted.
