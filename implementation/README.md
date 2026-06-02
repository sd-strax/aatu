# implementation/

Working folder for delivering aatu from cold start to v2 GA. Specs live in `design/` and are authoritative on *what to build*; this folder is about *how to build it, in what order, by whom, and against which risks*.

## Team shape (real)

- **Founder + architect** — sole human on engineering; supervises all output; makes architectural calls; owns customer conversations; runs strategy.
- **Claude Code** — implementation. Writes the Go backend, the TypeScript extension, adapters, tests, migrations, CI.
- **Claude Design** — UX. Surfaces, wireframes, interaction patterns, visual design.
- **Hunter (first hire, Month 5)** — fixture authoring, agent-loop prompt design, design-partner conversations, reasoning-quality testing. First actual person on the team after the founder.
- **Subsequent hires** — selectively, from ~Month 12 onward; see `roadmap.md` for ramp.

The throughput-shaping fact: code generation isn't the bottleneck. Founder review capacity is. Plans below are calendar-shaped accordingly.

## Relationship to `design/`

- `design/` answers "what is this thing?" — domain model, capability layer, action authorization, knowledge service, component topology, post-conclusion outputs, packaging, deployment shapes.
- `implementation/` answers "how do we get there?" — phased build plan, team ramp, module boundary in code, in-progress engineering decisions, risk register.

When implementation surfaces a question that should change the architecture, it gets resolved in `design/` (with cross-reference here). When the design is settled and the question is "how do we deliver it," that lives here.

## Files

| File | Purpose |
|---|---|
| `roadmap.md` | The phased build plan from cold start to GA. Calendar, headcount ramp, done-bars per cut (v0 / v1 / v2). Source of truth for sequencing. |
| `30-day-plan.md` | What to do *right now*. Hires, the first architectural commits, what to scope vs defer. |
| `module-layout.md` | Go package boundary between OSS and paid. The single most important architectural commit; doing this in Week 1 saves ~6 weeks later. |
| `phase-a-backbone.md` | Detailed scope for Phase A (the backbone). Other phase-detail files get authored as we approach each phase — don't write them all now; they will be wrong. |
| `risks.md` | Risk register with mitigations and triggers. Updated as risks materialize or retire. |
| `decisions.md` | Open engineering decisions and in-progress RFCs. A decision lands here when it's worth recording but not yet worth a spec edit; promotes to `design/` if it changes the architecture. |

## Conventions

- **Lightweight.** Working docs, not specs. Prefer terse and revisable over comprehensive and frozen.
- **Reference, don't restate.** Link to `design/<spec>.md §N` instead of repeating architectural decisions.
- **Phase-detail files appear when needed, not in advance.** Phase A scope is here from day one; Phase B detail gets authored when we're ~1 month from starting it. The roadmap names the phases; detail comes when it's actionable.
- **Decisions log is append-only.** Each entry dated. Once a decision is "landed," it's promoted (to a spec or to the codebase) and marked here as resolved.
