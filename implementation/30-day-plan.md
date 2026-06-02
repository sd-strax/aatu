# First 30 days

What gets done before any other engineering work makes sense. Seven concrete items; some hire-shaped, some commit-shaped. Each names its Definition of Done and what it unblocks.

## 1. Hire 2 senior Go backend engineers

**Why first:** They are the spine. The aggregate, capability resolver, action authorization machinery all sit in their hands for the first six months. Seniority matters more than headcount; do not skimp.

**Profile:** 8+ years backend Go in production. Event-sourcing experience strongly preferred. Postgres-deep. Distributed systems instincts. Comfortable owning a layer end-to-end.

**Definition of Done:** Both offers signed; both start within 60 days.

**Unblocks:** Phase A (backbone), Phase B (capability layer).

## 2. Hire a product designer

**Why first:** The investigation surface is the differentiator. Bringing design in *after* engineering builds the panels means rebuilding the panels. Bring them in at the start; they design the surface in parallel with the substrate being built.

**Profile:** Done complex tool UX. Figma + product taste; not marketing design. Comfortable with technical density (the analyst is a sophisticated user; this isn't consumer SaaS). Experience with developer tools or analyst tools strongly preferred.

**Definition of Done:** Offer signed; start within 60 days.

**Unblocks:** Phase D (agent loop + surfaces).

## 3. Begin hunter recruitment for Month 5

**Why now:** Hardest hire in the plan; takes ~2–3 months from start. If recruitment starts Month 1, candidate lands Month 4–5 exactly when fixture authoring + prompt engineering need them.

**Profile:** Active or recently active threat hunter / IR responder. Has worked in a mid-tier or enterprise SOC. Comfortable writing (SOPs, fixtures, internal docs). Open to a builder role, not just an advisor.

**Definition of Done:** Pipeline of 5+ qualified candidates by end of Month 1; first round of conversations underway.

**Unblocks:** Fixture-corpus authoring, agent-loop prompt design, design-partner conversations.

## 4. Land the Go package boundary (Week 1)

**Why first:** Single most leveraged architectural commit of the whole project. Costs ~1 week of focused work now; costs 4–6 weeks of refactor at v2 if skipped. The seam between OSS and paid modules has to be defined before any business logic gets written, or business logic ends up split across the boundary in ways that are hard to untangle.

**Output:** `module-layout.md` already drafted; the work is implementing it.
- Top-level Go module structure (`oss/`, `paid/tenancy/`, `paid/governance/`, `internal/...`)
- Interface contracts in `oss/` that `paid/*` packages implement
- Stub implementations in `paid/*` that compile and return "not enabled"
- Honor-system config flag that gates `paid/*` activation
- Build still produces a single binary; activation is runtime config

**Definition of Done:** Repo compiles. `go test ./...` passes (empty tests OK). A `paid_modules.tenancy.enabled` config flag flips a no-op switch. Sample command logs `tenancy module: disabled` at startup.

**Unblocks:** Phase A; everything downstream stays clean.

**Owner:** Founder/architect or first senior backend hire.

## 5. Stand up the bundled deps supervisor (Weeks 2–4)

**Why now:** Boring infra that everything depends on. Three managed processes (Postgres, Temporal, Keycloak) plus the aatu-backend supervisor. Get the supervisor right early because debugging a flaky supervisor mid-Phase B is miserable.

**Output:**
- `aatu start` brings up Pg + Temporal + Keycloak (single realm) + aatu-backend
- `aatu stop` performs orderly shutdown
- `aatu status` reports component health
- Cascading restart logic per `05 §3.1`: Temporal exits → restart; Postgres exits → fatal
- Platform packaging hooks (launchd / systemd / Windows service) drafted but not yet polished

**Definition of Done:** Demo run on macOS + Linux. `aatu start` → `aatu status` shows all healthy → kill Temporal → restarts cleanly → `aatu stop` → all gone. Postgres data at `~/.aatu/pg/`. Bundled Postgres 16+ with pgvector extension preinstalled.

**Unblocks:** Aggregate work (needs Postgres), Temporal workflows, Keycloak auth flow.

## 6. Start the agent-loop prompt-engineering research thread (Weeks 1–4, parallel)

**Why parallel with engineering:** Prompt engineering is *research*, not implementation. Reasoning quality, tool-call discipline, knowing-when-to-stop, retrieval-context budget tradeoffs — these aren't write-the-code-and-ship. Start iterating *now*, against mocked tool surfaces in a notebook or scratch project, so by the time the real engine is ready in Phase D, the prompt scaffolding is already validated.

**Output:** A scratch project (Python or TypeScript, doesn't matter) that:
- Mocks `list_capabilities`, `recall_sop`, `recall_similar_investigations`, and 3–5 read verbs returning canned OCSF
- Calls a real LLM (Claude/GPT/whatever) in a tool-calling loop
- Renders the reasoning trace, citations, hypothesis transitions

The point is to *learn what works* and *find what breaks* the LLM's tool discipline before committing to a system prompt and tool surface in the real engine. Treat as 2–3 months of concentrated iteration, owned by the founder/architect + hunter (when they land).

**Definition of Done (Month 1):** Scratch project exists; founder + first senior hire have run it against 5+ scenarios; have a first-cut system prompt and tool description format that the LLM uses without hallucinating tool names. Initial findings written up in `decisions.md`.

**Unblocks:** Phase D agent loop has a designed prompt to implement, not a research problem.

## 7. Engage a SOC 2 advisor (consultation only)

**Why now:** Not committing yet. But the SOC 2 calendar is the longest unmoveable item in the plan; need to understand what we're signing up for before committing. A 2-hour scoping call with a Vanta/Drata/Secureframe advisor (or a security consultancy) tells you Type I lead time, Type II observation length, what controls you need to have in place before engagement begins.

**Output:** Written summary of: minimum lead time from "ready to engage" to Type I completion; what controls and processes must exist before engagement; rough cost; recommended timing relative to v1/v2 roadmap.

**Definition of Done:** Summary in `decisions.md` under "SOC 2 timing decision (open)." Decision on when to actually engage (~Month 12 per current plan) is deferred until ~Month 9.

**Unblocks:** Aatu-hosted commercial readiness calendar is no longer a black box.

---

# What we do NOT do in the first 30 days

- **Hire SRE/devops.** Need at Month 5–7, not now. Backend engineers can run the bundled deps stack themselves until then.
- **Hire web frontend.** No web surface until Phase I (~Month 13). Premature.
- **Hire sales.** Pre-revenue. Bad fit and bad timing.
- **Engage SOC 2 formally.** Just the scoping call. Formal engagement at ~Month 12 when there's a real product to assess.
- **Write the rest of the Phase B/C/D scope files.** They will be wrong; we'll get them right closer to the work.
- **Decide on the canonical EDR / SIEM / IdP for v1 adapters.** Customer pull at end of v0 design-partner phase should drive this; deciding now risks building for the wrong vendor.
- **Pick the bundled embedding model.** v1 concern; defer.
- **Set up the CDN / signed-bundle pipeline.** Boring infra needed by Phase H (~Month 11–13); not now.

---

# Tracking

These seven items get checked off in `decisions.md` as they land. The plan revises monthly; if Month 1 reveals that one of these was misframed, the revision lands here, not in `roadmap.md` (which is the destination, not the path).
