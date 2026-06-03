# First 30 days

What gets done before any other engineering work makes sense. Reflects the actual team shape: founder + architect supervising Claude Code (engineering) and Claude Design (UX). Items are grouped by time horizon; each names its Definition of Done and what it unblocks.

---

## Week 1 — architectural commits

The three things that must land before any business logic is written.

### 1. Set up the Claude Code workflow

**Why first:** Throughput from Day 1 depends on Claude Code being productive in this codebase, with this architecture, against these specs. Wasting Week 1 on tooling pays back nothing; investing Week 1 in skills, settings, memory discipline, and review process pays back every week thereafter.

**Output:**
- Project-level `CLAUDE.md` in repo root (already exists; refine as architecture lands)
- Skills configured (a few small skills for: running tests, checking spec cross-refs, validating module-boundary invariants, generating adapter scaffolds)
- Settings/hooks for safety (deny destructive commands, gate sensitive paths)
- **OSS-leak prevention:** pre-commit hook on the public `aatu` repo that grep-checks the diff for confidentiality flags (e.g., `MSSP`, `conversion`, `revenue`, `burn`, `runway`, `Claude Code`, `founder`, `hunter` as person, `contractor`, `customer pull`, design-partner names, calendar dates). Not airtight — a sanity net that catches obvious accidents. The discipline lives in `CLAUDE.md`'s "Public/private boundary" section; the hook is the backstop.
- Memory discipline: project memory for architectural decisions, feedback memory for review patterns the founder repeats
- A `/review` or equivalent slash command that runs Claude over a diff with founder's review criteria

**Definition of Done:** Founder runs a sample task end-to-end through Claude Code — writes a small adapter scaffold, gets it reviewed, gets it tested, merges it — without any tooling-side friction. Time-from-spec-to-merged-PR is measurable. Pre-commit hook is installed in the public repo skeleton (the repo itself lands as part of item 2) and flags a deliberately-confidential test phrase.

**Unblocks:** Everything else.

### 2. Land the two-repo OSS / paid boundary

**Why first:** Single most leveraged architectural commit of the whole project. ~1 week of focused work now; saves 4–6 weeks of refactor at v2 and avoids a high-stakes split right before OSS goes public. The seam between OSS and paid modules is a *repo boundary* — public `aatu`, private `aatu-enterprise` — not a folder boundary.

**How this gets done:** Founder writes the architectural decisions (repo layout, interface signatures, binary-naming convention), Claude Code implements both repo skeletons, founder reviews and corrects. Spec reference is `implementation/module-layout.md`.

**Definition of Done:**
- Public `aatu` repo: compiles, `go test ./...` passes (empty tests OK), `module/` interfaces + disabled stubs land, `cmd/aatu version` runs, single test proves disabled-stub behavior.
- Private `aatu-enterprise` repo: depends on `aatu` as a Go module, `tenancy/` and `governance/` stubs land, paid `cmd/aatu version` reports as paid build, single integration test proves the config flag flips activation correctly.
- `go.work` set up locally so Claude Code can edit both repos against each other.
- D13 (two-repo decision) recorded in `decisions.md`; D1 marked superseded.

**Unblocks:** Phase A; everything downstream stays clean. The repo boundary makes Phase H OSS launch a non-event — the public repo IS what goes public.

### 3. Start the agent-loop prompt-engineering research thread

**Why parallel with engineering:** Prompt engineering is *research*, not implementation. Founder does this directly — it's the same shape of work as Claude Code supervision and builds the founder's fluency for both jobs. Starts Week 1, iterates through Month 4.

**Output:** A scratch project (Python or TypeScript) that:
- Mocks `list_capabilities`, `recall_sop`, `recall_similar_investigations`, and 3–5 read verbs returning canned OCSF
- Calls a real LLM in a tool-calling loop
- Renders the reasoning trace, citations, hypothesis transitions

The point is to learn what works and what breaks the LLM's tool discipline before committing to a system prompt and tool surface in the real engine. Treat as 2–3 months of concentrated iteration. Owned by founder; hunter joins from Month 5.

**Definition of Done (Month 1):** Scratch project exists; founder has run it against 5+ scenarios; has a first-cut system prompt and tool description format the LLM uses without hallucinating tool names. Initial findings written up in `decisions.md`.

**Unblocks:** Phase D agent loop has a designed prompt to implement, not a research problem.

---

## Weeks 2–4 — the supervised stack

### 4. Stand up the bundled deps supervisor

**Why now:** Boring infra that everything depends on. Three managed processes (Postgres, Temporal, Keycloak) plus the aatu-backend supervisor. Get the supervisor right early because debugging a flaky supervisor mid-Phase B is miserable.

**How this gets done:** Founder spec'd; Claude Code implements; founder tests by running it on a clean macOS box and a clean Linux VM. Iterate on what breaks.

**Output:**
- `aatu start` brings up Pg + Temporal + Keycloak (single realm) + aatu-backend
- `aatu stop` performs orderly shutdown
- `aatu status` reports component health
- Cascading restart logic per `05 §3.1`
- Platform-native service hooks drafted (launchd / systemd / Windows service)

**Definition of Done:** Founder demos a clean install + start + status + simulated crash + restart + stop on macOS and Linux. Pg data persists across restart. Bundled Postgres 16+ with pgvector preinstalled.

**Unblocks:** Aggregate work (needs Postgres), Temporal workflows, Keycloak auth flow.

---

## Ongoing through Month 1

Items that start in Week 1 and run continuously; their Definition of Done is a Month-1 milestone, but the artifact (hire / rhythm) lands later.

### 5. Begin hunter recruitment for Month 5

**Why now:** Hardest hire in the plan; takes ~2–3 months from cold start. The only person joining the team in the first half-year. If recruitment starts Month 1, candidate lands Month 4–5 exactly when fixture authoring + prompt engineering need them.

**Profile:** Active or recently active threat hunter / IR responder. Has worked in a mid-tier or enterprise SOC. Comfortable writing (SOPs, fixtures, internal docs). Open to a builder role at an unconventional company shape (solo founder + AI engineers). Knows OCSF, MITRE ATT&CK, and the realities of EDR/SIEM/IdP integration. The first non-founder team member; treat the search seriously.

**Definition of Done (Month 1):** Pipeline of 5+ qualified candidates; first round of conversations underway. Candidate fit on the "OK with AI-driven engineering team" question explicitly tested.

**Unblocks:** Fixture-corpus authoring, agent-loop prompt design, design-partner conversations.

### 6. Establish the founder's review and audit rhythm

**Why now:** With Claude Code as the engineering team, founder's review discipline *is* the quality bar. Without a deliberate rhythm, code quality drifts and the codebase becomes one person's mental model.

**Output:**
- Daily review cadence (PRs / patch sets reviewed daily, not batched)
- Weekly architecture audit (one focused hour reviewing what Claude built that week against `design/`)
- Monthly codebase walkthrough — founder records a 20-min walkthrough of recent areas (for future hires, for the second engineer who joins Month 12–14, for advisors and design partners)
- A second-pair-of-eyes plan: contract a senior engineer for periodic deep code review starting ~Month 6 (4 hours/month, escalating); see R10 in `risks.md`

**Definition of Done (Month 1):** First weekly architecture audit happens. First monthly walkthrough recorded. Contractor engagement plan in `decisions.md`.

**Unblocks:** Code quality stays defensible; bus factor mitigated; future hires have something to walk into.

---

# What we do NOT do in the first 30 days

- **Hire backend engineers.** Claude Code + founder review IS the engineering team. Hire a senior engineer at Month 12–14 for codebase stewardship before paid modules.
- **Hire a designer.** Claude Design + founder direction. UX hire only if Claude Design output proves insufficient on the investigation surface (re-evaluate at v1 launch).
- **Hire SRE/devops.** Bundled deps until Phase J. Re-evaluate at GA prep.
- **Hire sales.** Pre-revenue. Bad fit and bad timing.
- **Engage SOC 2 — even informally.** The only product surface that needs aatu-side SOC 2 is aatu-hosted; that's a limited preview at v2 GA and the commitment to it isn't due until Phase J planning (~Month 9). Self-hosted distributions (OSS and paid) inherit the customer's compliance posture — aatu has no audit story to defend in those shapes. Revisit SOC 2 calendar when aatu-hosted preview is committed.
- **Decide v1 canonical adapters.** Design-partner pull drives this; defer to ~Month 7.
- **Boil the ocean on Claude Code tooling.** Skills, hooks, memory discipline — yes. Building your own custom toolchain — no.
- **Skip the contractor code review.** The temptation to "we're moving fast, no need" is the path to the codebase nobody else can take over.

---

# Tracking

These six items get checked off in `decisions.md` as they land. The plan revises monthly; if Month 1 reveals that one of these was misframed, the revision lands here, not in `roadmap.md` (which is the destination, not the path).
