# Risks

Living register. Each risk has a description, likelihood/impact, mitigation, and trigger (the signal that the risk is materializing). When a risk materializes, it moves to "Active." When it retires, it moves to "Resolved."

## Active

*(none yet — Phase A in setup)*

## Watching

### R1 — Agent-loop prompt engineering is research, not implementation

**L/I:** High / High
**Why:** Reasoning quality, tool-call discipline, retrieval-context budget tradeoffs aren't write-the-code-and-ship. Treating it as engineering schedules a research problem on the wrong calendar.
**Mitigation:** Start the prompt scaffolding research thread in Week 1 against mocked tool surfaces (per `30-day-plan.md` item 6). Iterate for 2–3 months before Phase D needs an answer. Owned by founder/architect + hunter.
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

**L/I:** Certain / Medium (high impact only for regulated buyers)
**Why:** Type I window + Type II observation = ~12 months from engagement to defensible attestation. If aatu-hosted GA commercial release is gated on Type II, calendar adds ~12 months to anything regulated.
**Mitigation:** Engage SOC 2 advisor at Month 1 (scoping only). Formal engagement at ~Month 12 (mid-Phase H). Type II observation runs Phase K → post-GA. Ship aatu-hosted as **limited preview** at GA; full commercial-with-Type-II lands post-GA. Self-hosted paid is unaffected — customer owns data, no aatu-side attestation needed.
**Trigger:** Month 9 and SOC 2 engagement still hasn't started — by then the timing is locked in.

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
**Mitigation:** Plan for *continuous adapter expansion* as a permanent line item from v1 onward — 1 engineer at 50% utilization on adapters as a steady state. Community adapter-contribution path (TR-9) reduces but does not eliminate this.
**Trigger:** 3+ customer asks for the same uncovered adapter in the first 90 days post-v1 launch.

## Resolved

*(none yet)*

---

## How to use this file

- Read at the start of each month.
- For each "Watching" risk, check the trigger. If triggered, move to "Active" and the assignee owns mitigation.
- When a risk is mitigated past the point of concern, move to "Resolved" with a one-line note on why.
- Add new risks as they surface.
