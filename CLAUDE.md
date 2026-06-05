# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository nature

This repo is the **reckon OSS engine** — design specifications today, code starting Week 1 of Phase A. Currently private on GitHub; goes public at Phase H. **Treat every edit as if it's already public.**

Paid modules and commercial strategy live in the separate private repo `reckon-enterprise` (`github.com/sd-strax/reckon-enterprise`). That repo depends on this one as a Go module and implements the `module/` interfaces; this repo has zero awareness of it. The repo boundary is the architectural enforcement of the open-core split.

See "Public OSS posture" below — it is load-bearing for every edit.

## The product (reckon)

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
- **Open core: paid layers on OSS, no overlap.** OSS engine lives in `reckon` (public-bound); paid modules live in a separate private `reckon-enterprise` repo that depends on `reckon` as a Go module and implements its `module/` interfaces. OSS has zero awareness of paid; the repo boundary enforces this. See `implementation/module-layout.md`.

## Public OSS posture

This repo is destined to be public OSS. Every edit must respect that. The following kinds of content do **not** belong here — they belong in `reckon-enterprise`:

- **Buyer profiles** ("MSSP," "in-house SOC," "the buyer pays per...")
- **Conversion economics** (revenue framing, conversion events, pricing/licensing terms beyond "licensing is bolt-on")
- **Commercial commitments** ("the product won't," "no third conversion hook")
- **Team-shape framing** (founder, Claude Code, Claude Design, hunter, contractor, hiring, calendar weeks/months)
- **Customer-specific context** (design partners by name, customer pull anecdotes, internal stakeholder names)
- **Competitive positioning vs SOAR/EDR/SIEM vendors by name** (generic capability comparisons are fine)

What stays here: architectural facts — what the codebase does, how it's structured, the rationale for the tradeoffs a contributor would need to understand.

**When in doubt, write the sentence in `reckon-enterprise`** and surface only the architectural distillation here, if any survives.

A pre-commit hook lands in Week 1 alongside Claude Code workflow setup (per `reckon-enterprise/30-day-plan.md` item 1) to catch obvious commercial keywords on commit. It is a backstop; the discipline lives here.

## Conventions in the prose

- **"v0"** means the mock-fixtures prototype, not a shipping version. Many decisions are explicitly deferred to v1+ and called out as such — preserve those deferrals when editing.
- **Custom STIX objects** use the `x-` prefix per STIX convention: `x-hypothesis`, `x-prediction`, `x-action`, `x-host`, `x-registry-key`, `x-scheduled-task`, `x-group`, `x-interpretation`.
- **"Adopted vs invented"** sections (e.g., `01-domain-model.md`) are load-bearing — they justify why something isn't a new primitive. Don't invent without updating these.
- Specs end with **"Open questions" / "Deferred to v1+"** sections that are deliberate non-decisions; the model accommodates either resolution. Treat these as part of the design, not as TODOs.

## Working in this repo

- When adding a new spec, follow the existing structure: framing/scope → out-of-scope → numbered sections → end-of-spec marker. Cross-reference other specs with section numbers (e.g., "see §4.3"), not page numbers.
- Engineering planning (roadmap, 30-day plan, decisions log, risk register, phase-by-phase scope) lives in `reckon-enterprise` because it's framed around team shape, calendar, and commercial context. Architectural seam docs (`implementation/module-layout.md`) live here because they describe the codebase any contributor would see.
- Cross-references go OSS → OSS only. **Do not reference `reckon-enterprise` paths from any file in this repo.** If you find yourself wanting to, the content you're describing probably belongs over there, and what's in this repo should stand on its own architectural merit.

## Go conventions

We adopt industry-standard public Go conventions rather than maintaining our own style guide. Read these in order:

1. **[Google Go Style Guide](https://google.github.io/styleguide/go/)** — canonical reference. Style Guide + Style Decisions + Best Practices.
2. **[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)** — the actual review checklist.
3. **[Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)** — supplementary; especially the mutex placement and error wrapping sections.
4. **`implementation/reckon-patterns.md`** — the small set of patterns specific to this codebase that the public guides don't address. ~5–6 patterns total. Read once; cite from new code as needed.

`make lint` runs `golangci-lint` with a config (`.golangci.yml`) tuned to enforce most of the above mechanically — `staticcheck`, `errcheck`, `gosec`, `revive`, `gocritic`, `govet`, `bodyclose`, `errorlint`, `unused`. `make ci` (lint + test + build) is the pre-commit / pre-PR check.

When extending the code, prefer references to the public guides over re-arguing style locally. When a project-specific pattern emerges three+ times, add it to `reckon-patterns.md`.
