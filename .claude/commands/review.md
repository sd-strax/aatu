---
description: Review the current diff against project review criteria
---

Run a focused code review on the current diff (or the commit range I name). Apply these criteria in order:

## 1. Architectural boundaries

OSS code must not import `github.com/sd-strax/aatu-enterprise/...`. The `module/` package is the only seam between OSS and paid; everything else in OSS calls *only* through `module/` interfaces.

If you find a paid-shaped need that an interface doesn't cover, flag it as a candidate `module/` interface extension — that's the right resolution, not reaching around.

## 2. Public OSS posture

This repo is destined for public OSS at Phase H. Flag any introduction of:

- **Buyer profiles** — `MSSP`, `MDR`, "in-house SOC," "the buyer pays per..."
- **Conversion economics** — revenue framing, conversion events, pricing/licensing terms beyond "licensing is bolt-on"
- **Commercial commitments** — "the product won't," "no third conversion hook"
- **Team-shape framing** — founder, Claude Code, Claude Design, hunter (as person), contractor, hiring, calendar weeks/months
- **Customer-specific context** — design partners by name, "customer pull" anecdotes
- **Competitive positioning by vendor name** — generic capability comparisons fine; named comparisons not

See `CLAUDE.md` "Public OSS posture" for the full list and rationale.

## 3. Spec alignment

For changes under `design/*.md`:
- Cross-references (`§N.M`) still resolve.
- Architectural commitments listed in `CLAUDE.md` are not contradicted.
- Section structure preserved (framing → out-of-scope → numbered sections → end marker).

## 4. No business logic in skeleton work

Through Phase A, the work is interface seams, stubs, and supervisor wiring. Resist adding logic prematurely. If a logic change looks necessary, it usually belongs in the phase that owns that domain (B for capability layer, C for action authz, etc.).

## 5. Test coverage on contracts

Interface changes (`module/`), config schema changes, and runtime entry-point changes need tests asserting the contract. No untested edits to those.

---

## Output format

For each issue:
- `[BLOCKING]` — must fix before commit
- `[NIT]` — worth fixing but doesn't block
- `[OK]` — section reviewed, nothing found

Surface specific `file:line` for each finding. End with a one-line summary: "Ready to commit" or "N blocking issues, M nits."
