# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Repository nature

This repo contains **design specifications only** — no code, no build, no tests. All work happens in `design/*.md`. There is no toolchain to run; review and revise prose. When asked to "implement" something, the work is to update the relevant spec and reconcile it with the others.

## The product (aatu)

"Cursor for SOC analysts" — an AI-native investigation environment for threat hunters and IR responders (not T1/T2 triage). Substrate: **VS Code extension (primary), CLI (secondary), Java backend, Next.js frontend, MCP for tool federation**. v0 prototype runs against mock MCP servers via fixtures, not real tenants.

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

## Conventions in the prose

- **"v0"** means the mock-fixtures prototype, not a shipping version. Many decisions are explicitly deferred to v1+ and called out as such — preserve those deferrals when editing.
- **Custom STIX objects** use the `x-` prefix per STIX convention: `x-hypothesis`, `x-prediction`, `x-action`, `x-host`, `x-registry-key`, `x-scheduled-task`, `x-group`, `x-interpretation`.
- **"Adopted vs invented"** sections (e.g., `01-domain-model.md`) are load-bearing — they justify why something isn't a new primitive. Don't invent without updating these.
- Specs end with **"Open questions" / "Deferred to v1+"** sections that are deliberate non-decisions; the model accommodates either resolution. Treat these as part of the design, not as TODOs.

## Working in this repo

- The `design/` directory is currently untracked in git; the prior tracked copies were at the repo root (`04-action-authorization.md`, `03-capability-layer.md`, `01-domain-model.md`, `02-persistence.md`) and show as `deleted` in `git status`. This is in the middle of a reorganization — confirm with the user before staging or committing the moves.
- When adding a new spec, follow the existing structure: framing/scope → out-of-scope → numbered sections → end-of-spec marker. Cross-reference other specs with section numbers (e.g., "see §4.3"), not page numbers.
