# private/

Everything in this directory is **confidential**. None of it goes to the public OSS repo when it is created at Phase H.

## What lives here

- **`pitch.md`** — GTM positioning, target buyers, "the bet."
- **`roadmap.md`** — calendar estimates, headcount ramp, burn-rate framing.
- **`30-day-plan.md`** — first-month concrete actions, including hunter recruitment, internal review rhythm, Claude Code workflow setup.
- **`phase-a-backbone.md`** — Phase A engineering scope, framed around founder + Claude Code ownership.
- **`decisions.md`** — engineering decisions log, including pending decisions whose context is commercial (SOC 2 timing, vendor priority, team hires).
- **`risks.md`** — risk register including team-shape risks (founder throughput cap, bus factor, burnout, buyer perception).
- **`implementation-readme.md`** — the original `implementation/` README, framing the workspace's purpose and team shape.
- **`open-core-rationale.md`** — the commercial framing extracted from `design/05 §13.6` (conversion hooks, buyer profiles, the "no third hook" commitment).

## What the public repo does not contain

When the public OSS repo `aatu` is created:

- Everything in this `private/` directory is **excluded**.
- Specs (`design/`) carry over **sanitized**: architectural facts stay; buyer profiles, conversion economics, commercial commitments, and team-shape framing are removed.
- `implementation/module-layout.md` carries over as architectural documentation; team-internal framing has already been removed.
- The public repo gets fresh `README.md`, `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md` written for OSS audience — they don't derive from anything in this private repo.

## Discipline going forward

Every commit to the public OSS repo (once it exists) needs to pass two checks:

1. **Content check.** Does this commit reference, hint at, or reveal: pricing, burn, hiring, customer names, design-partner conversations, founder/Claude-Code team shape, calendar dates, revenue, conversion economics, "the bet," competitive positioning vs SOAR/EDR/SIEM vendors by name? If yes, the content belongs here in `private/`, not in the public repo.
2. **Cross-reference check.** Does this commit reference a file or section that lives in `private/`? If yes, either remove the reference or rewrite the referenced content in a way that doesn't require the private context.

A pre-commit hook in the public repo (added during Week 1 Claude Code workflow setup) catches the obvious cases by keyword. It is not a substitute for thinking.

## Why this split exists

A public OSS repo with `paid/` folders, conversion-economics framing, or team-shape context reads as OSS-adjacent, not as a real OSS commitment. The dominant open-core pattern — Mattermost / Grafana / Sentry / Vault — is two repos with a clean public face. The conscious decision: confidential business material never flows into the OSS repo.