# 06 — VS Code Surface Map

The designs describe the whole IDE, but **most of that chrome is native VS Code.** This file
tells you which is which.

## What is a webview (you build it in HTML/CSS/JS)

| Surface | Notes |
|---|---|
| **Investigation Panel** | `WebviewViewProvider` in the secondary sidebar or a `WebviewPanel` beside the editor. This is the main build. |
| **Enhanced `.inv.md` preview** | `CustomTextEditorProvider` — gives you the enhanced render while the underlying document stays plain markdown. |
| **Entity popover** | Rendered inside whichever webview hosts the chip. Position with `position: fixed` + viewport clamping (never let it clip). |
| **Verdict / conclude dialogs** | Modal inside the webview — VS Code has no rich modal API. |
| **Settings page** | Optional: a `WebviewPanel` for the rich tool-health view. Simple prefs should also exist in `contributes.configuration`. |

## What is native VS Code API (do **not** rebuild in HTML)

| Surface | API |
|---|---|
| Investigation Explorer tree | `TreeDataProvider` + `contributes.views` in a custom `viewsContainer` |
| Activity bar icon + badge | `contributes.viewsContainers.activitybar`; `TreeView.badge` |
| Editor tabs, title bar | native — nothing to do |
| Status bar items | `window.createStatusBarItem` (3 items — see below) |
| Command palette | `contributes.commands` with the `reckon:` category |
| Keybindings | `contributes.keybindings` |
| Context menus | `contributes.menus` (`view/item/context`, `editor/context`) |
| Toasts / notifications | `window.showInformationMessage` / `Warning` / `Error` with action buttons |
| Editor decorations (evidence gutter pins) | `createTextEditorDecorationType` |
| File watching | `workspace.createFileSystemWatcher('**/*.inv.md')` |

Toasts are native `showInformationMessage`, never a webview-drawn component — the native one
respects the user's notification settings.

## Commands to contribute

```
reckon.newInvestigation      reckon: New Investigation          ⌘⇧I / ctrl+shift+I
reckon.openInvestigation     reckon: Open Investigation         ⌘⇧O / ctrl+shift+O
reckon.focusPanel            reckon: Focus Investigation Panel  ⌘⇧E / ctrl+shift+E
reckon.togglePanel           reckon: Toggle Investigation Panel
reckon.pinEvidence           reckon: Pin Evidence               (editor context, has selection)
reckon.pivotEntity           reckon: Pivot on Entity            (editor context)
reckon.searchInLogs          reckon: Search in Logs             (editor context)
reckon.setVerdict            reckon: Set Verdict
reckon.changeStatus          reckon: Change Status
reckon.concludeInvestigation reckon: Conclude Investigation
reckon.archiveInvestigation  reckon: Archive Investigation      (tree context)
reckon.retryAction           reckon: Retry Action               (tree context, action node)
reckon.reverseAction         reckon: Reverse Action             (tree context, action node)
reckon.waiveAction           reckon: Waive Action               (tree context, action node)
reckon.followUp              reckon: Send Follow-up             (tree context, external node)
reckon.escalate              reckon: Escalate                   (tree context, external node)
reckon.openSettings          reckon: Open Settings
```

Gate the palette with `when` clauses (`reckon.hasActiveInvestigation`,
`reckon.status == 'REMEDIATING'`) so irrelevant commands don't surface.

## Tree view structure

```
▾ ACTIVE (2)
  ▾ 🔴 Suspicious PowerShell on WIN-FIN-04      [REMEDIATING] ⚠
      🚩 Verdict: malicious
    ▾ Actions (5/6)
        ✓ Isolate WIN-FIN-04
        ✓ Isolate WIN-HR-12
        ✓ Revoke sessions jchen@acme.local
        ✓ Reset password jchen@acme.local
        ✗ Block 185.220.101.42 (failed)
        ⏳ Purge phishing emails ⚠
    ▾ External Work (1/2) ⚠
        ✉ Slack → #it-operations              ⏰
        📋 ServiceNow INC0042871: Reimage      ⚠
  ▸ Invoice-lure phishing wave                 [ACTIVE]
▾ PAUSED (1)
▾ DRAFT (1)
▸ CONCLUDED (3)
```

- Group by status; `CONCLUDED` collapsed by default and searchable.
- Row description: `<Status> · N entities · <age>`.
- Status dot colors: ACTIVE info · PAUSED/VERDICT_REACHED warning · REMEDIATING danger ·
  DRAFT muted · CONCLUDED indigo · ARCHIVED faint.
- `⚠` badge when an escalation policy has triggered; `⏰` when a follow-up is due.
- Use `ThemeIcon` with `ThemeColor` for state glyphs so they theme correctly.

## Status bar (3 items, right-aligned except the first)

| Item | Content | Click |
|---|---|---|
| Investigation | `$(shield) inv-2026-0425-7741 · Remediating · 4/6 actions` | focus panel |
| Tools | `$(layers) 4/5 tools` | open settings |
| Model | `$(sparkle) Claude Sonnet 4.6` | open settings |

Add a verdict item when set. The whole bar takes on the indigo `--statusbar-bg` treatment during
an active investigation and reverts to the standard background once `CONCLUDED`.

## Webview hardening

- Set a strict CSP; load all scripts/styles from `webview.asWebviewUri` with a nonce.
- `retainContextWhenHidden: true` on the panel — losing streamed state on tab switch is unacceptable.
- Persist view state via `getState`/`setState` so a reload restores scroll and pending input.
- Bundle fonts locally (a webview must never pull from a CDN). Ship Open Sans + JetBrains
  Mono as extension assets, or fall back to `--vscode-font-family` /
  `--vscode-editor-font-family`.
- All extension↔webview traffic goes through `postMessage`. Suggested message names mirror the
  stream events in `05-data-model.md` § 5.5, plus UI intents:
  `ui.submitQuery`, `ui.slashCommand`, `ui.approveAction`, `ui.rejectAction`,
  `ui.confirmT3`, `ui.retryAction`, `ui.reverseAction`, `ui.waiveAction`,
  `ui.pinEvidence`, `ui.sendComms`, `ui.acknowledgeReply`, `ui.followUp`,
  `ui.escalate`, `ui.closeInvestigation`, `ui.openEntity`.

## Editor decorations

Evidence pins in the reasoning section get a gutter icon (amber pin) plus a subtle line
highlight, so pinned findings are visible in the **raw** document too — not only in the
enhanced preview.

## Configuration (`contributes.configuration`)

```
reckon.backendUrl                string   https://reckon.acme.internal/api/v0
reckon.investigationsDir         string   ${workspaceFolder}/investigations
reckon.model                     enum     claude-sonnet-4.6 | claude-opus-4.6 | claude-haiku-4.5
reckon.streaming.enabled         boolean  true
reckon.streaming.showToolStatus  boolean  true
reckon.followUp.defaultHours     number   48
reckon.escalation.enabled        boolean  true   (v0: surfaces prompts, never auto-fires)
reckon.trustTierCeiling          enum     T1 | T2 | T3
```

Tool connections and escalation policies live in `.reckon/config.yaml` in the workspace, surfaced
read-mostly in the settings webview.

## Deliberately out of scope for v0

Multi-analyst collaboration · web frontend · CLI · T1/T2 triage queue UX · hypothesis-rooted
hunting entry · cross-investigation memory · auth/RBAC/multi-tenancy · alert ingestion pipeline.

Leave visual and interaction room for the action tiers — don't foreclose them.
