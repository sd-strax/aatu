---
description: Review the current diff against project review criteria
---

Run a focused code review on the current diff (or the commit range I name). Apply these criteria in order. **Always run `make lint` first** — that catches the mechanical issues. Then do the review for what lint can't see.

## Step 0: mechanical baseline

Run `make lint` (or `golangci-lint run ./...` directly). Surface any issues it flags. The configured rule set covers: `errcheck`, `staticcheck`, `gosec`, `revive`, `gocritic`, `govet`, `bodyclose`, `errorlint`, `unused`, `ineffassign`, `misspell`, `unconvert`, `copyloopvar`. If anything fires, fix or justify before reviewing further.

Also run `make test` and confirm green.

## Step 1: Go style conformance

Review against the canonical references (in order of authority):

1. **[Google Go Style Guide](https://google.github.io/styleguide/go/)** — Style Guide + Style Decisions + Best Practices. Most authoritative.
2. **[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)** — the original Go-team review checklist. Especially:
   - Error wrapping with `%w`
   - Error strings: lowercase, no trailing punctuation
   - Receiver names: short, consistent across methods
   - Variable naming
   - `if` block error handling style (indent-error-flow)
   - Pass by value vs pointer
   - Naked returns only in short functions
   - `context.Context` as first arg
3. **[Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)** — supplementary. Especially mutex placement (next to field it protects), error wrapping nuances, channel sizes, table-driven tests.

## Step 2: aatu-specific patterns

See `implementation/aatu-patterns.md`. Verify the change conforms to whichever applies:

- **Pure function + transaction wrapper** layering for command handlers
- **`supervisor.Component` lifecycle contract** for new components (Start blocks until ready; Stop idempotent; Health concurrency-safe)
- **Two-axis auth chain** for HTTP routes (Gate 1 RequireAuth + per-route role gate; never mix with Gate 2 action authorization)
- **Dependency injection by connection string + handler** for server config (deps as strings, not as component pointers)
- **Embedded fs.FS for SQL migrations** per engine subpackage
- **Test infra** with `flag.Parse()` before `testing.Short()` and named cleanup before `os.Exit`/`log.Fatalf`

## Step 3: architectural boundaries

- OSS code must not import `github.com/sd-strax/aatu-enterprise/...`. The `module/` package is the only seam between OSS and paid.
- `aatu/internal/` packages can only be imported by `aatu/` subpackages.
- The `server/` package may import `aggregate/` and `authz/`; `supervisor/` may not.
- `aatu/cmd/aatu` wires everything together; engine subpackages should not import from `cmd/` (the dependency direction is the other way).

## Step 4: public OSS posture

This repo is destined for public OSS. Flag any introduction of:

- **Buyer profiles** — `MSSP`, `MDR`, "in-house SOC," "the buyer pays per..."
- **Conversion economics** — revenue framing, conversion events, pricing/licensing terms beyond "licensing is bolt-on"
- **Commercial commitments** — "the product won't," "no third conversion hook"
- **Team-shape framing** — founder, Claude Code, Claude Design, hunter (as person), contractor, hiring, calendar weeks/months
- **Customer-specific context** — design partners by name, "customer pull" anecdotes
- **Competitive positioning by vendor name** — generic capability comparisons fine; named comparisons not

See `CLAUDE.md` "Public OSS posture" for the full list and rationale.

## Step 5: test coverage on the change

- **Interface changes** (`module/`, `Handler`, `Verifier`, etc.) need tests asserting the contract.
- **Config schema changes** need tests in `config/`.
- **Runtime entry-point changes** need tests covering the new behavior.
- **HTTP routes** need at least one test per status-code branch (`200`/`201`, `400`, `401`/`403`, `404`/`500`).
- **Concurrent code** (mutex / channel / goroutine logic) needs `-race` tests.

If the change adds new functionality without a test, that's a `[BLOCKING]` finding.

## Step 6: changelog & doc

- Updated `aatu-enterprise/decisions.md` if an architectural decision landed?
- Updated `implementation/aatu-patterns.md` if a new pattern emerged that will be used 3+ times?
- Updated `CLAUDE.md` if a load-bearing convention changed?

---

## Output format

For each issue:
- `[BLOCKING]` — must fix before commit (lint failures, missing tests on new code, OSS-leak, architectural boundary violations)
- `[NIT]` — worth fixing but doesn't block (style deviation that the linter doesn't catch, naming nits, doc gaps)
- `[OK]` — section reviewed, nothing found

Surface specific `file:line` for each finding. End with a one-line summary: "Ready to commit" or "N blocking issues, M nits."
