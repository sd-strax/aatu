# Roadmap — cold start to v2 GA

The build plan distilled. Three cuts (v0 / v1 / v2), eleven phases, ~20-month calendar, team ramps from 5 to 19. Updated as phases retire or risks materialize.

## The three cuts

| Cut | Audience | What's true | What's not yet |
|---|---|---|---|
| **v0** | Internal + 3–5 design partners under NDA | Real engine, real LLM reasoning, real audit chain — against fixture data | No real integrations; no public release |
| **v1** | Public early-access OSS on GitHub | Real read+write integrations, real SOAR delegation, OSS single-tenant fully functional | No paid tier; no MSSP consolidation; no shared investigation |
| **v2 GA** | Public commercial launch — sellable | Paid tenancy + governance modules live; self-hosted GA; aatu-hosted limited preview | Aatu-hosted SOC 2 Type II (post-GA); `ScheduledInvestigationWorkflow`; Sub-path B |

GA = v2 = the moment the open-core thesis is testable in the field.

## Phases

```
PHASE A — Backbone                              Month 1–3
   supervised process model (Pg + Temporal + Keycloak + backend)
   aggregate (event store, projections, optimistic concurrency)
   JWT/authz middleware
   paid-module package boundary (empty stubs)

PHASE B — Capability layer + fixtures           Month 3–5
   capability resolver
   adapter runtime (JSON-RPC over stdio)
   fixture adapter + first 3 fixture scenarios
   normalizer registry + first normalizers
   identity resolver

PHASE C — Action + knowledge                    Month 4–6   (parallel with B)
   action authorization machinery (trust tiers, CEL, policies)
   ActionLifecycle / ReversalSaga Temporal workflows
   knowledge service core (SOP CRUD, lightweight mode, keyword retrieval)

PHASE D — Agent loop + surfaces                 Month 5–8
   VS Code extension scaffolding (auth, WS, panels)
   agent loop (BYOK, tool dispatch, transcript, implicit retrieval)
   action review panel, SOP editor, knowledge browser
   CLI (init, start, stop, status, backup)
   ===== V0 DESIGN-PARTNER DONE-BAR =====

PHASE E — Real read adapters                    Month 8–11
   1 EDR (CrowdStrike most likely; MCP or native)
   1 SIEM (Splunk or Sentinel)
   1 IdP (Okta or Entra)
   1 TI platform
   1 case-management (TheHive or ServiceNow)
   cross-cutting concerns actively exercised

PHASE F — Real write + SOAR delegation          Month 9–12  (parallel with E)
   write-side adapter contract finalized
   3 real write adapters (host.isolate, account.disable, ioc.publish)
   SOAR_PLAYBOOK adapter (Tines or Torq, real)

PHASE G — Knowledge v1                          Month 10–12 (parallel with E/F)
   embeddings (bundled local ONNX + BYOK provider)
   SummarizeForKnowledgeIndex Temporal workflow
   similarity-based retrieval

PHASE H — Lifecycle workflow + OSS launch       Month 11–13
   InvestigationLifecycleWorkflow (v1 Temporal orchestrator)
   docs site, contribution guide, CI, security policy, GitHub Actions
   ===== V1 OSS PUBLIC LAUNCH =====

PHASE I — Paid module boundary fills in         Month 13–16
   tenancy module: tenant_id RLS, multi-realm Keycloak, vault, lift workflow
   governance module: tenant-admin UI, federation helpers, signoff queues
   citation analytics, auditor export
   web review panel (Next.js)

PHASE J — GA infra                              Month 14–17 (parallel with I)
   approval relay service
   transactional email integration
   shared investigation (NOTIFY/LISTEN + presence)
   BackgroundHuntWorkflow
   self-hosted Terraform/Helm artifacts
   aatu-hosted production env (limited preview)

PHASE K — Compliance + launch                   Month 15–20 (parallel with I/J)
   SOC 2 engagement (starts mid-Phase H, ~Month 12)
   Type I window during Phase J
   Type II observation runs Phase K → post-GA
   GA launch readiness (sales, billing, support, marketing)
   ===== V2 GA =====
```

The critical path is A → B → C → D → E → I → K. Parallelism opportunities sit in E/F/G, in I/J, and in K (compliance runs on its own calendar).

## Calendar — realistic estimate

| Stage | Wall clock | Why |
|---|---|---|
| Cold start → v0 design-partner ready | ~6–8 months | Founder-bottlenecked review of Claude-generated code; agent-loop prompt engineering (research, not implementation); hunter recruitment runs in parallel |
| v0 → v1 OSS public launch | ~5–7 months | Five real adapters calendar-bound by vendor APIs; OSS launch overhead unchanged; hunter onboarded helps with adapter validation |
| v1 → v2 GA | ~7–9 months | Two paid modules + GA infra + self-hosted artifacts + aatu-hosted env + SOC 2 prep + first non-founder engineer ramping on codebase |
| **Cold start → GA** | **~20–22 months** | Plan for 24 to absorb what we don't see coming |

The wall-clock is similar to a small-team plan, but the cost shape is wildly different (~$0.5–1.5M total burn through GA vs $5–8M). Code generation isn't the slow part — review, integration, vendor-API integration, customer conversations, and architectural decisions are. AI augmentation accelerates code but not those.

## Team ramp (real)

```
Month            1   3   5   7   9   11  13  15  17  19  21
──────────────────────────────────────────────────────────
Founder / arch   1   1   1   1   1   1   1   1   1   1   1
Hunter           -   -   1   1   1   1   1   1   1   1   1
Senior Eng       -   -   -   -   -   -   1   1   1   1   1
2nd Hunter / SE  -   -   -   -   -   -   -   -   1   1   1
Customer success -   -   -   -   -   -   -   -   -   1   1
Sales            -   -   -   -   -   -   -   -   -   -   1
──────────────────────────────────────────────────────────
Total            1   1   2   2   2   2   3   3   4   5   6
```

**Implicit team members (not on payroll):**
- **Claude Code** — implementation throughout
- **Claude Design** — UX throughout
- **Founder time on review** is the throughput cap, not the headcount

**Key hires and timing rationale:**

- **Hunter (Month 5).** Hardest hire; start recruitment Month 1. Drives fixture quality, agent-loop prompt design, reasoning-quality testing, design-partner conversations. First real person after founder. Treat as a peer, not a function.
- **Senior engineer (Month 12–14).** Right after v1 OSS launches, right before v2 paid-module deep dive. Two reasons: (1) second pair of eyes on a codebase nobody but the founder has touched — the bus-factor problem, real by Month 12; (2) capacity to take Phase I/J ownership while founder focuses on customer-facing GA prep and Phase K. Should be someone who's done event-sourcing + multi-tenant SaaS. Hiring this person blind into a Claude-written codebase is risky — see R10.
- **Customer success (Month 19).** When paid customers exist or are imminent.
- **Sales (Month 21).** At GA; paid customers need a deal closer.

**What's deliberately absent vs the original team plan:**
- No backend engineers in months 1–11. Claude Code + founder review.
- No designer. Claude Design + founder direction.
- No SRE/devops. Bundled deps + bare cloud infra handled by founder + Claude through GA prep; SRE-shaped hire considered only if scale demands.
- No PM. Founder is the PM.

**What's still real:**
- The hunter hire. AI doesn't replace domain expertise on the SOC side.
- Customer-facing roles. Trust is built person-to-person, not AI-to-prospect.
- A senior engineer for codebase stewardship before paid modules — not technical capacity, *succession risk* mitigation.

## Done-bars per cut

**v0 design-partner done-bar (end of Phase D)**

A friendly hunter sits down at a laptop, runs `aatu init`, opens a fixture scenario, runs a real investigation end-to-end:

- Open seed → agent reasons against fixture data → propose action → gate fires (T1 auto, T2 single confirm, T3 typed challenge) → analyst approves → reversal works → conclusion → post-conclusion pipeline runs → SOP gets written → next investigation reasons against it.

They give an opinion on the surface, the reasoning quality, the audit story. No public release. The point is product-feedback density.

**v1 OSS public launch done-bar (end of Phase H)**

The product can be installed by anyone reading the GitHub README and configured against:
- 5 real read adapters (EDR + SIEM + IdP + TI + CM)
- 3 real write adapters
- 1 real SOAR_PLAYBOOK adapter

Public OSS posture: stars, docs, community channels, contribution guide. Sellable? No. Credibility-building, starts the MSSP-per-client adoption motion.

**v2 GA done-bar (end of Phase K)**

Paid distribution ships in both shapes:
- Paid self-hosted is commercial, billable, supported
- Paid aatu-hosted is in limited preview pending SOC 2 Type II

MSSP can adopt OSS per-client and consolidate to paid multi-tenant on a single Terraform-deployable customer-hosted instance. In-house SOC can buy paid self-hosted for governance/SSO without ever needing tenancy. Sales motion, billing, support — all live. SOC 2 Type II in observation window, completes post-GA.

## What's deferred to post-GA

- `ScheduledInvestigationWorkflow` (cron-shaped repeating hunts)
- Sub-path B (joining an existing tenant)
- Aatu-hosted SOC 2 Type II completion
- Detection authoring tooling (v2+ per the specs)
- Mobile, MSP/hierarchical tenancy, cross-tenant indicator pool (all already deferred to v3+ in specs)
- Per-tenant analytics surface (CISO dashboards, MTTR, etc.) — derivable from event stream, surface bolted on post-GA
- Cross-client analyst console for MSSPs — deferred per `05 §16`
- Cross-org peer benchmarks — v3+ alongside cross-tenant indicator pool

## Cross-references

- `30-day-plan.md` — concrete first-month actions
- `module-layout.md` — Go package boundary the Phase A work hangs off
- `phase-a-backbone.md` — Phase A detailed scope
- `risks.md` — risk register
- `design/00-summary.md` §v0/v1/v2 staging — architectural cut definitions; this roadmap implements them
- `pitch.md` — external positioning
