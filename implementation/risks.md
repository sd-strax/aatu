# Risks

Living register. Each risk has a description, likelihood/impact, mitigation, and trigger (the signal that the risk is materializing). When a risk materializes, it moves to "Active." When it retires, it moves to "Resolved."

## Active

*(none yet — Phase A in setup)*

## Watching

### R1 — Agent-loop prompt engineering is research, not implementation

**L/I:** High / High
**Why:** Reasoning quality, tool-call discipline, retrieval-context budget tradeoffs aren't write-the-code-and-ship. Treating it as engineering schedules a research problem on the wrong calendar.
**Mitigation:** Start the prompt scaffolding research thread in Week 1 against mocked tool surfaces (per `30-day-plan.md` item 5). Iterate for 2–3 months before Phase D needs an answer. Owned by founder/architect + hunter (from Month 5). Founder's daily Claude Code supervision builds prompt-engineering fluency that transfers directly.
**Trigger:** Phase D Month 5 starts and the prompt scaffolding has only been touched in the last month, not 3+ months.

### R2 — Fixture authoring underestimated

**L/I:** High / Medium
**Why:** A realistic OCSF scenario the agent can reason over plausibly takes ~1–2 weeks of hunter time. Need 8–10 scenarios by v0 done-bar. That's 12 weeks of focused hunter effort just on fixtures.
**Mitigation:** Hire hunter at Month 5 (recruitment from Month 1). Treat fixture authoring as a primary deliverable for the hunter, not a side task. Consider contracting a second hunter for additional scenario authoring during Phase C–D.
**Trigger:** End of Phase C and fewer than 4 scenarios are at "the agent reasons over them plausibly" quality.

### R3 — Write-side adapter contract slippage

**L/I:** Medium / High
**Why:** Deferred in the specs (`03 §10`) but blocks all v1 actions. If it slides to end of Phase F instead of front, v1 actions ship late or thinly.
**Mitigation:** Land the contract at the front of Phase F (Month 9). Treat it as a v0+1 thread that gets resolved before Phase E adapters get too far. Track separately from Phase F adapter delivery.
**Trigger:** Phase E Month 10 and the contract is still in draft / under debate.

### R4 — OSS launch overhead

**L/I:** Medium / Medium
**Why:** Docs site, contribution guide, security disclosure policy, CI for community PRs, issue templates, community moderation — non-trivial work that competes with feature development.
**Mitigation:** Budget 1.5 engineer-months across Phase H specifically for OSS launch readiness, *separate from* feature work. Don't treat as a side task.
**Trigger:** Phase H Month 12 and no docs site / no contribution guide exists.

### R5 — SOC 2 calendar gates aatu-hosted commercial readiness

**L/I:** Certain / Medium (high impact only for regulated buyers; zero impact on self-hosted)
**Scope:** This risk applies *only* to aatu-hosted. Self-hosted distributions (OSS and paid) inherit the customer's compliance posture — no aatu-side attestation needed.
**Why:** Type I window + Type II observation = ~12 months from engagement to defensible attestation. If aatu-hosted GA commercial release is gated on Type II, calendar adds ~12 months to anything regulated.
**Mitigation:** SOC 2 advisor scoping call deferred to Month 9–10 — when Phase J planning solidifies the aatu-hosted preview commitment. Formal engagement at ~Month 12 (mid-Phase H) per roadmap Phase K. Type II observation runs Phase K → post-GA. Ship aatu-hosted as **limited preview** at GA; full commercial-with-Type-II lands post-GA. Limited preview is invite-only design partners who accept the assurance posture — no Type II needed for that stage.
**Trigger:** Month 10 and the advisor scoping conversation still hasn't happened — by then the formal-engagement timing starts slipping.

### R6 — BYOK LLM economics as a buyer-side headwind

**L/I:** Medium / Low
**Why:** Every analyst pays Anthropic/OpenAI directly. At intensive use, $100–$500/month/analyst. Buyers will ask "can't aatu bundle inference?" Bundling breaks the security and pricing stories.
**Mitigation:** Hold the line. Defend in every commercial conversation. Articulate why (no LLM key in backend → no aatu-side data exposure; analyst keeps control of their LLM bill; no aatu-side inference cost padded into per-seat). Optional: bundled local model for embeddings only (already in spec) as a partial answer.
**Trigger:** N/A — recurring conversation, not a one-time event.

### R7 — MSSP consolidation lift is real engineering, not config

**L/I:** Medium / High
**Why:** Sub-path A done properly is ~6–8 weeks of senior backend time: event replay across instances, content-hash side-store transfer, identity continuity, embedded credential rotation. Underestimate it and v2 GA slips or ships without a working consolidation story (which kills the MSSP conversion).
**Mitigation:** Allocate 8 weeks of senior backend time at the start of Phase I specifically for the lift workflow. Don't bundle it with other tenancy-module work.
**Trigger:** End of Phase I and the lift workflow is still missing the side-store transfer step or the identity continuity check.

### R8 — Adapter coverage expectations post-launch

**L/I:** Certain / Medium
**Why:** v1 ships 5 read + 3 write adapters. Customers immediately ask about adapter #6, #7, #8. Without continuous adapter capacity, customer #2 sees a thin connector list and bounces.
**Mitigation:** Plan for *continuous adapter expansion* as a permanent line item from v1 onward. With Claude Code as the engineering team, each new adapter is days-to-weeks rather than weeks-to-months — but founder review is still a cap. Community adapter-contribution path (TR-9) reduces but does not eliminate this.
**Trigger:** 3+ customer asks for the same uncovered adapter in the first 90 days post-v1 launch.

### R9 — Founder is the throughput cap

**L/I:** Certain / High
**Why:** Claude Code can generate code faster than founder can review it. The bottleneck is review capacity, not generation. If founder gets pulled into multiple parallel reviews, none get done well; if founder gets sick, distracted, or stuck on a hard problem, the project stalls.
**Mitigation:**
- Strict daily review cadence — don't batch.
- Don't run more than 2 substantial Claude Code threads in parallel without explicit hand-offs.
- Weekly architecture audit catches drift early before it compounds.
- Pair complex changes with deliberate spec updates *first* (specs in `design/` are the input to Claude; precise specs reduce review burden).
- See R10 — second pair of eyes from Month 6.
**Trigger:** Backlog of un-reviewed PRs / patches exceeds one week. Or: founder skips two consecutive weekly architecture audits.

### R10 — Bus factor of 1 on the codebase

**L/I:** High / High
**Why:** For the first ~12 months, only the founder has seen any of the code. If founder is unavailable, the project stops cold. By Month 12 the codebase is large enough that a new engineer can't ramp on it in a sprint. The first non-founder engineering hire (Month 12–14) is going into a codebase nobody else has touched.
**Mitigation:**
- Engage a senior engineer contractor from ~Month 6 for periodic deep code review (4 hrs/month → 8 hrs/month → 16 hrs/month). They don't write code; they audit, ask questions, push back on architectural choices. Second pair of eyes plus a person who knows the codebase if founder disappears.
- Monthly codebase walkthrough recordings (per `30-day-plan.md` item 7).
- Architecture decisions land in `design/` (already true) — codebase is reproducible from specs if the worst happens.
- Hire the Month 12–14 senior engineer with codebase-stewardship as the explicit job, not just feature delivery. Budget 6 weeks of ramp before they're independently productive.
**Trigger:** Month 4 and no contractor engagement happened. Or: codebase grows to >50k LOC without external review.

### R11 — Code quality drift from Claude Code patterns

**L/I:** Medium / Medium
**Why:** Claude Code writes patterns the founder doesn't catch; over months these accrete. Examples: over-abstracted interfaces, inconsistent error handling, premature optimization, test patterns the founder doesn't realize are anti-patterns. The codebase becomes correct line-by-line but unmaintainable in aggregate.
**Mitigation:**
- Establish style guide / project conventions early (in `CLAUDE.md` or a `STYLE.md`) and update as patterns surface.
- Run a *codebase audit pass* every 2 months — founder reads non-recent code with fresh eyes and notes drift.
- Contractor (R10) catches what the founder is blind to.
- Refactor opportunistically; don't let cruft compound.
**Trigger:** Founder finds themselves saying "I don't remember writing this" or "I wouldn't have done it this way" more than once a month.

### R12 — Founder burnout

**L/I:** Medium / High
**Why:** Solo founder doing engineering review + architecture + customer conversations + recruiting + strategy for 12–18 months. Months 1–5 are especially intense (no hunter yet; no contractor yet). Burnout doesn't show up as a milestone slip; it shows up as decision fatigue, dropped balls, then a sudden break.
**Mitigation:**
- Hunter at Month 5 is partly a wellness move — first person to talk to about the work in deep technical terms.
- Contractor at Month 6 reduces decision load on architecture and code review.
- Don't compress the calendar. The roadmap is 20–22 months; trying to do it in 14 is the burnout path.
- Take real breaks. The work compounds; brief absences don't kill it; not taking breaks does.
**Trigger:** Two consecutive weeks of working past 10pm. Or: skipped weekly audit two months in a row. Or: founder hasn't talked to a non-Claude entity for 72 hours.

### R13 — Buyer perception of an AI-driven engineering team

**L/I:** Medium / Low–Medium
**Why:** Some buyers love "solo founder + AI agents" as a future-of-work signal. Others see it as risk — "what if Anthropic shuts down? what if you get hit by a bus? who supports us?" Regulated buyers may flag it in security reviews.
**Mitigation:**
- Don't lead with it in sales conversations. Lead with the product, the architecture, the audit story, the open-core posture.
- Have honest answers ready when asked: "The codebase is open-source from v1; specs in `design/` are authoritative and reproducible; we have contractor backup and a permanent senior engineer from Month 12+." All of which is true under this plan.
- The first senior engineer hire makes this conversation easier. Schedule them in time for the GA sales motion.
**Trigger:** First buyer explicitly raises this as a concern; track frequency.

## Resolved

*(none yet)*

---

## How to use this file

- Read at the start of each month.
- For each "Watching" risk, check the trigger. If triggered, move to "Active" and the assignee owns mitigation.
- When a risk is mitigated past the point of concern, move to "Resolved" with a one-line note on why.
- Add new risks as they surface.
