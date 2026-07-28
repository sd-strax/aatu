# 07 — Build Order

Each phase is independently demoable. Don't start a phase until the previous one's acceptance
criteria pass — the value compounds in this order.

---

## Phase 1 — Design tokens & webview shell

Emit the token set from `01-design-system.md` as CSS custom properties, deriving chrome-adjacent
values from `--vscode-*`. Build the empty Investigation Panel: context bar, chat scroll region,
composer. Bundle fonts locally.

**Done when:** the panel renders at the right density in both dark and light VS Code themes,
fonts load offline, and the composer grows/submits correctly.

---

## Phase 2 — File as artifact

`.inv.md` read/write with frontmatter parse + merge. Scaffold-on-create. Enhanced preview
(`CustomTextEditorProvider`) with the frontmatter card and an empty `## Reasoning`. Raw toggle.
File watcher + reconcile.

**Done when:** `⌘⇧I` creates a real file that opens in the editor; editing it in vim and
returning reconciles without data loss; the file is valid markdown on GitHub.

---

## Phase 3 — Tree, status bar, commands

`TreeDataProvider` grouped by status, all commands and keybindings, three status bar items,
editor and tree context menus.

**Done when:** every surface shows the same status simultaneously, and the analyst can drive
create/open/focus entirely from the keyboard.

---

## Phase 4 — Streaming & tool calls

Wire the SSE/WS stream. Build the tool-call block with the full status sequence, coverage pills,
raw JSON, and fan-out. Word-granular text streaming. `file.append` mid-stream.

**Done when:** a question produces first token < 3s p50; a fan-out shows fast tools resolving
while a slow one still spins; the file visibly grows before the prose finishes; every claim is
traceable to raw JSON in one click.

*This is the phase that makes or breaks the product. Budget accordingly.*

---

## Phase 5 — Entities & evidence

Entity chips everywhere (ids are engine-minted — binding §1), popover with
cross-investigation lookup, aliasing, pivot. Evidence pinning from every surface. **Evidence
in reach** (`02 §2.8`): every cited ref opens the raw record read-only — this ships in the
same phase as pinning because pins without openable citations are labels, not evidence.

**Done when:** the same IP in two investigations resolves to one id; pinning from any surface
updates every view together; clicking any cited ref anywhere opens the underlying OCSF
event / STIX node in one click.

---

## Phase 6 — Verdict & lifecycle

Slash autocomplete, the `/verdict` dialog with **preflight checklist + coverage residual**
(`02 §2.10`), `/status` with precondition preflight, `/hypothesis` and the **drivable
hypothesis tracker** (`02 §2.9`). Derived presentation states (verdict-reached,
remediating — binding §2.4).

**Done when:** the verdict dialog shows the gate state *before* submission with unmet items
linked to their remedy (the engine's rejection message is never the first thing the analyst
sees); the residual panel lists unavailable verbs, evidence-of-absence results, and untested
predictions at the moment of judgment; a verdict renders the investigation as
verdict-reached rather than closing it.

---

## Phase 7 — Remediation

Action cards in all engine states (including `PARTIAL` with per-target residuals,
reversal-attempted, and the expired posture — binding §2.3), **decision-grade** per
`03 §3.3`: countdown, reversibility class, escalation reason, dispatch route. Plan block
with grouping, T2 approval, T3 typed challenge, retry-as-new-action with lineage, reverse,
summary bar with nearest-expiry, closure preflight.

**Done when:** nothing executes without explicit approval; an approval card answers why /
on what evidence / what will execute / how undoable / how long before the window closes —
without leaving the card; a succeeded reversible action produces a paired reversal entry
(both retained) and a BEST_EFFORT reversal never claims REVERSED; closure preflight blocks
until every action is terminal.

---

## Phase 8 — Comms, follow-up, escalation

Preview-before-send for all channels, comms cards, inbound reply handling, inline reply composer,
follow-up timers and prompts, escalation policy surfacing, incident channel, templates, and
closure gating on open threads.

**Done when:** a message can't be sent without confirming a preview; a reply arriving while the
panel is closed produces a notification and a tree badge, and is waiting at the top of the panel
on next open.

---

## Cross-cutting acceptance

Validate these continuously, not at the end:

- [ ] Every surface renders engine state; on divergence the backend wins (binding §1).
- [ ] Analyst-authored acts are attributed events and are never overwritten by the AI.
- [ ] Every tool call exposes query, summary, coverage, and raw response.
- [ ] Every cited evidence ref, anywhere, opens the underlying record in one click.
- [ ] "No data" and "not configured" render as information, never as errors — and
      evidence-of-absence results are pinnable as findings.
- [ ] No action or message executes without explicit analyst confirmation.
- [ ] Every engine gate has a preflight surface; rejection messages are the fallback.
- [ ] Approval windows are visibly counting down wherever an approval is offered.
- [ ] Status is correct in every surface at once (document, panel, tree, status bar).
- [ ] Closing and reopening VS Code days later restores exact state from the backend.
- [ ] The exported markdown is something an analyst would paste into a ticket unedited.

## Success signals (from the original brief)

An analyst drives the flow unaided in under 15 minutes. They describe it as *"an IDE for
investigations"* and *"the file is the point."* They ask, unprompted, **"can I plug in my tools?"**
and they keep the `.inv.md` open after the demo ends.

**Rethink signal:** if they tab to the chat panel and ignore the file, the file isn't
load-bearing and the whole thesis is failing.
