# Engineering decisions log

Append-only. Each entry: date, decision, context, alternatives considered, who decided. When a decision changes the architecture, it's also reflected in `design/` and cross-referenced. When a decision is operational (no architectural impact), it lives only here.

A decision is "pending" until it lands. "Landed" when it's reflected in code and/or specs. "Superseded" if a later decision replaces it.

## Pending

### D1 — Build configuration: Option A (single binary) vs Option B (build tags)

**Status:** Pending — must land in Week 1 alongside `module-layout.md` implementation.
**Default recommendation:** Option A (single binary, runtime config) through v2 GA. Evaluate Option B post-GA if open-source community asks for it.
**Why default:** One CI matrix, one release artifact, one set of integration tests. The seam — what matters architecturally — is identical in both options.
**Decider:** Founder/architect + first senior backend engineer.

### D2 — Postgres migration tooling

**Status:** Pending — Week 4 alongside schema bootstrap.
**Candidates:** `migrate` (golang-migrate), `goose`, `sqlc`-driven schema management, `atlas`.
**Lean:** `migrate` — boring, widely used, plays well with embedded Postgres. But owner decides.
**Decider:** Backend engineer #1.

### D3 — Temporal SDK version and pinning policy

**Status:** Pending — Phase A.7.
**Notes:** Temporal SDK and dev server versions need to track each other. Decide a pin policy (LTS-track vs latest) before workflows get coded against a specific API. Lock down the dev-server version we build against.
**Decider:** Backend engineer #1.

### D4 — SOC 2 advisor / consultancy engagement

**Status:** Pending — Month 1 (scoping call only).
**Output:** Written summary in this file under "Landed" once consultation completes.
**Decider:** Founder.

### D5 — Canonical EDR / SIEM / IdP / TI / CM for v1 adapter set

**Status:** Pending — defer until end of v0 design-partner phase (~Month 7).
**Why defer:** Customer pull from design partners should drive vendor priority. Picking now risks building for the wrong vendor.
**Decider:** Founder/architect + hunter + first 2–3 design partners.

### D6 — Bundled local embedding model

**Status:** Pending — Phase G concern.
**Candidates per `06-knowledge-service.md §15`:** BGE-small, MiniLM, equivalent.
**Tradeoff:** Model size in binary vs retrieval quality.
**Decider:** Backend engineer responsible for Phase G + hunter.

### D7 — VS Code extension framework choice

**Status:** Pending — early Phase D.
**Candidates:** Plain VS Code Extension API (TypeScript) vs framework-on-top (Reactive Extensions / explicit MVVM patterns). Webview UI: React vs Solid vs Svelte.
**Lean:** Plain VS Code API + React for webviews. But TS engineer who owns Phase D decides.
**Decider:** First TS engineer (hired by Month 3).

### D8 — Telemetry / observability backend for production

**Status:** Pending — Phase A.8 (local mode) and Phase J (production).
**Candidates:** Self-hosted OTel collector + Grafana, vs SaaS (Honeycomb / Datadog / etc.). Production-only concern; local mode just emits to stderr + rolling file.
**Decider:** SRE/devops hire (Month 5–7) + founder.

## Landed

*(none yet)*

## Superseded

*(none yet)*

---

## Prompt-engineering research findings

Separate section, accreting as the research thread (item 6 of `30-day-plan.md`) produces learnings. Each entry dated; not a decision in the formal sense, but findings that inform Phase D implementation.

### Findings log (empty — populated as the scratch project runs)

*(awaiting first iteration)*
