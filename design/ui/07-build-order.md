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

Entity registry with UUIDv5, chips everywhere, popover with cross-investigation lookup, aliasing,
pivot. Evidence pinning from panel, file selection, and `/pin`, with gutter decorations.

**Done when:** the same IP in two investigations resolves to one id; pinning from any surface
updates frontmatter, panel, file, and counts together.

---

## Phase 6 — Verdict & lifecycle

Slash autocomplete, `/verdict` confirmation dialog, `/status` with precondition validation,
`/hypothesis`. Full state machine including `VERDICT_REACHED`.

**Done when:** concluding without evidence is blocked with a clear reason; verdict moves the
investigation to `VERDICT_REACHED` rather than closing it.

---

## Phase 7 — Remediation

Action model and state machine, action cards in all states, plan block with grouping, T2 approval,
T3 typed challenge + second approver, retry/reverse/waive, summary bar, `## Remediation` output,
closure prompt and `## Conclusion`.

**Done when:** nothing executes without explicit approval; a failed action can be retried and a
succeeded reversible action produces a paired reversal entry (both retained); closure is blocked
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

- [ ] Panel and file never disagree; on divergence the file wins.
- [ ] Analyst edits in `## Reasoning` survive the next AI turn.
- [ ] Every tool call exposes query, summary, coverage, and raw response.
- [ ] "No data" and "not configured" render as information, never as errors.
- [ ] No action or message executes without explicit analyst confirmation.
- [ ] Status is correct in all four places at once (file, panel, tree, status bar).
- [ ] Closing and reopening VS Code days later restores exact state from the file.
- [ ] The produced `.inv.md` is something an analyst would paste into a ticket unedited.

## Success signals (from the original brief)

An analyst drives the flow unaided in under 15 minutes. They describe it as *"an IDE for
investigations"* and *"the file is the point."* They ask, unprompted, **"can I plug in my tools?"**
and they keep the `.inv.md` open after the demo ends.

**Rethink signal:** if they tab to the chat panel and ignore the file, the file isn't
load-bearing and the whole thesis is failing.
