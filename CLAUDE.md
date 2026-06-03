# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository nature

This repo contains **design specifications and engineering planning** — no code yet; Phase A engineering work starts Week 1. Design work happens in `design/*.md`; planning lives in `private/`. When asked to "implement" something, the work today is to update the relevant spec and reconcile it with the others.

**This repo is private. A subset of its content is destined for the public OSS repo `aatu` at Phase H.** See "Public/private boundary" below — it is load-bearing for every edit.

## The product (aatu)

"Cursor for SOC analysts" — an AI-native investigation environment for threat hunters and IR responders (not T1/T2 triage). Substrate: **VS Code extension (primary), CLI (secondary), Go backend, transport-neutral capability layer for tool federation** (adapter classes: MCP, NATIVE_API, CUSTOM, FIXTURE, SOAR_PLAYBOOK; see `design/03-capability-layer.md` §5.4). v0 prototype runs against OCSF fixtures via the fixture adapter, not real tenants.

Two workflows, same loop, different entry points: **investigation** (entity-rooted) and **hunt** (hypothesis-rooted).

## The four specs and how they fan in

The specs are not independent — they reference each other and each declares its own scope and out-of-scope items. Treat them as a single coupled design.

| Spec | Owns | Depends on | Flagged contributions to others |
|---|---|---|---|
| `design/01-domain-model.md` | What an investigation IS | — (foundational) | Defines all primitives the others build on |
| `design/02-persistence.md` | How investigation state is stored | domain model (authoritative) | Event taxonomy, AI reasoning persistence layers |
| `design/04-action-authorization.md` | Action authorization, trust tiers | domain model | Adds 7 values to `interpretation_type` enum; new `x-action` primitive; new `reverses` edge type |
| `design/03-capability-layer.md` | LLM↔tool surface (verbs, adapters, normalization) | domain model | Identity computation rules; deviates from strict STIX 2.1 for `process`, `email-addr`, `user-account` |

When changing one spec, scan the others for cross-references. `04-action-authorization.md` §10 explicitly lists what it adds back to the domain model; `03-capability-layer.md` §7 explicitly notes its STIX deviations. These are the seams.

## Architectural commitments (load-bearing across specs)

These are decisions that have been ruled out of re-litigation in `01-domain-model.md`. Don't propose changes to them without explicit user direction:

- **Two-layer graph.** Telemetry layer = raw OCSF events, immutable. Interpretation layer = STIX-shaped objects, mutable. Joined by typed edges, never by embedding.
- **STIX 2.1 vocabulary** for the interpretation layer; **OCSF** for telemetry payloads. Adopted, not invented.
- **Identity is deterministic UUIDv5** (STIX rules). Same entity → same id across producers and investigations. Aliasing is an explicit edge, never a destructive merge.
- **Investigation = STIX Grouping + four extensions** (Seed, Lifecycle, ReasoningThread, ConclusionSlot).
- **`x-interpretation` is the only invented primitive** in the domain model. Hypotheses, predictions, findings are outputs of Interpretations, not separate primitives. (`04-action-authorization.md` adds `x-action` as a sibling, with explicit justification.)
- **Investigation aggregate is event-sourced; everything else is CRUD + thin history.** Postgres single events table, no ES framework. Atomic event-append + projection-update in one transaction.
- **AI is a delegate, never a principal.** Every event records a human principal; `actor.delegate` captures the AI. Authorization is the *intersection* of principal permissions and delegate policy.
- **Capability layer is pure I/O + normalization.** It does not reason, never produces `x-interpretation`, always emits `derivation_mode = DIRECT`. Only exception: detection_finding normalizer (`03-capability-layer.md` §4.12).
- **Blast radius, not action verb, drives the trust tier.** T2→T3 escalator at >10 distinct targets is non-negotiable in code, only adjustable.
- **Open core: paid layers on OSS, no overlap.** OSS engine lives in `aatu` (public-bound); paid modules live in a separate private `aatu-enterprise` repo that depends on `aatu` as a Go module and implements its `module/` interfaces. OSS has zero awareness of paid; the repo boundary enforces this. See `implementation/module-layout.md`.

## Public/private boundary

This repo is private. The public OSS repo `aatu` doesn't exist yet (it lands at Phase H). Until then, every edit to public-bound content must respect the boundary in advance.

- **`private/` is never public.** Files there don't go to the OSS repo. **Do not reference `private/` paths from any file outside `private/`.** (`grep` for cross-refs after moving anything in or out of `private/`.)
- **Public-bound today:** all of `design/` (sanitized), `implementation/module-layout.md`. Everything else under the repo root that isn't in `private/` should be reviewed before being treated as public-bound.
- **Sanitization principles for public-bound content** — architectural facts stay; the following come out:
  - Buyer profiles ("MSSP," "in-house SOC," "the buyer pays per...")
  - Conversion economics (revenue framing, conversion events, pricing/licensing terms beyond "licensing is bolt-on")
  - Commercial commitments ("the product won't," "no third conversion hook")
  - Team-shape framing (founder, Claude Code, Claude Design, hunter, contractor, hiring, calendar weeks/months)
  - Customer-specific context (design partners by name, customer pull anecdotes)
  - Competitive positioning vs SOAR/EDR/SIEM vendors by name (generic capability comparisons are fine)
- **When in doubt, write the sentence in `private/`** and link to or paraphrase it from the public doc only if the architectural-fact distillation works without the private context.

## Conventions in the prose

- **"v0"** means the mock-fixtures prototype, not a shipping version. Many decisions are explicitly deferred to v1+ and called out as such — preserve those deferrals when editing.
- **Custom STIX objects** use the `x-` prefix per STIX convention: `x-hypothesis`, `x-prediction`, `x-action`, `x-host`, `x-registry-key`, `x-scheduled-task`, `x-group`, `x-interpretation`.
- **"Adopted vs invented"** sections (e.g., `01-domain-model.md`) are load-bearing — they justify why something isn't a new primitive. Don't invent without updating these.
- Specs end with **"Open questions" / "Deferred to v1+"** sections that are deliberate non-decisions; the model accommodates either resolution. Treat these as part of the design, not as TODOs.

## Working in this repo

- When adding a new spec, follow the existing structure: framing/scope → out-of-scope → numbered sections → end-of-spec marker. Cross-reference other specs with section numbers (e.g., "see §4.3"), not page numbers.
- Engineering planning (roadmap, 30-day plan, decisions, risks, phase-by-phase scope) lives in `private/` because it's framed around team shape and timelines. Architectural seam docs (`implementation/module-layout.md`) live outside `private/` because they describe the codebase any contributor would see.
