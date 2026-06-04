---
description: Run the Go test suite for this repo
---

Run `make test` from the repo root (which invokes `go test ./...`). Report pass/fail counts and surface the names + error excerpts of any failing tests. On a clean pass, summarize the package count and test count.

If `make` is unavailable in the environment, fall back to `go test ./...` directly — same effect.

Don't run `go vet` or linters unless explicitly asked. For the full pre-commit checklist (vet + test + build), use `make ci`.
