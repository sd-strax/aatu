# 02 — Investigation Core

## 2.1 The `.inv.md` editor view

The file is the artifact. Two render modes, toggled by a sticky segmented control at the top
of the editor ("Enhanced" / "Raw .md") with the hint *"Valid markdown — renders in vanilla
VS Code & GitHub too."*

Implement Enhanced as a **custom editor / webview preview**; Raw is the plain text document.
The extension must never require itself to read the file.

### Frontmatter card
YAML frontmatter renders as a structured card, never raw YAML.

**Header row** — 40px seed icon (alert-colored, `--ent-alert`), then:
- Title, 20px/700, `letter-spacing: -.01em`
- Investigation id, 12px mono, `--text-3`
- Badge row: status badge + verdict badge

**Status badge** — pill, 11px/700, `letter-spacing: .04em`, 7px leading dot:
| Status | Color / bg |
|---|---|
| `DRAFT` | `--text-2` on `--fill-2` |
| `ACTIVE` | info; dot has `0 0 0 3px rgba(74,168,255,.18)` glow |
| `PAUSED` | warning |
| `VERDICT_REACHED` | warning |
| `REMEDIATING` | danger; dot glows `rgba(255,95,110,.16)` |
| `CONCLUDED` | `--he-primary-soft` on `rgba(115,113,252,.14)` |
| `ARCHIVED` | `--text-3` on `--fill`, whole view reads grayed/read-only |

**Verdict badge** — pill, uppercase 11px/700: `pending` (muted, not uppercase), `benign` (success),
`suspicious` (warning), `malicious` (danger) with a flag glyph.

**Metadata grid** — 2 columns, 1px gaps showing as hairlines: Seed · Created · Updated ·
Conclusion. Labels 10px uppercase `letter-spacing:.08em` `--text-3`; values 13px, mono for timestamps.

**Entities block** — label "Entities · N", filter chips (All / Subject / Suspicious), then one
row per entity: entity chip + optional alias link (`⇄ alias` in 11px) + role tag right-aligned
(`subject` info, `suspicious` danger, `related` neutral).

**Evidence block** — "Pinned evidence" + amber count pill. Each item: amber card
(`--warn-bg` / `--warn-bd`), pin glyph, finding text (13px), source line
(`tool/operation` in mono `--he-primary-soft` + pinned timestamp). Entrance uses `pinIn`.
Empty: italic *"No evidence pinned yet — pin findings from the reasoning trace or the panel."*

**Remediation block** (appears once a plan exists) — counts: N succeeded / pending / failed /
waived / external, each in its semantic color.

### `## Reasoning` — append-only trace

Section heading: 20px/700 with a faint mono `##` prefix in `--text-4` (a deliberate nod to the
markdown source), plus an entry count in 12px `--text-3`.

Each entry is a **timeline node**:
- 2px vertical rail at `left: 6px`, `--border`; last entry's rail stops at 50%.
- 14px node circle at `left: 0`, `background: editor-bg`, 2px border — primary for AI,
  `--ent-domain` green for analyst — with a 5px inner dot.
- Header: mono time (12px/600) · title (14px/600) · author pill (`AI` indigo / analyst green,
  10px/700 uppercase) · optional right-aligned amber "evidence" flag.
- Body: "Tools called" eyebrow → tool-call blocks → optional result table → "Interpretation"
  eyebrow → prose.

**Pinned entries** get `background: linear-gradient(90deg, var(--warn-bg), transparent 60%)`,
a 3px amber left bar, and shift padding to keep the node aligned.

**Analyst annotation** — when the analyst disagrees, an inline block: green left border 3px,
`--ent-domain-bg`, eyebrow "ANALYST NOTE". These are never overwritten by the AI.

**Verdict entry** — mono block on `--bad-bg`/`--bad-bd` showing the literal
`/verdict <disp> — <rationale>`.

**Empty state** — centered, 46px sparkle glyph at 50% opacity, "No reasoning yet", and
*"Ask a question in the Investigation Panel. The AI federates across your tools and appends a
timestamped, structured entry here — the file grows as you work."*

### Raw mode
Monospace, 13px, `line-height: 1.7`, syntax-tinted: YAML keys `--ent-host`, string values
`--ent-domain`, list dashes `--text-4`, markdown headings `--he-primary-soft`, fences `--text-4`.
Must be byte-accurate to what's on disk.

---

## 2.2 Investigation Panel (webview)

446px, right side. Vertical stack:
`context bar → [remediation summary] → [incident channel] → chat scroll → input`

### Context bar
- Row 1: 26px logo mark · title (13px/700, ellipsis) · status badge + verdict · action icons
  (clear ↻, pause/resume, conclude 🔒, archive), 26px hit targets, hover `--hover`.
- Row 2: metadata chips (11px, `--fill` on `--border-2`, pill): entities · evidence · steps · model.
- Background: `linear-gradient(180deg, var(--elevated), var(--panel-bg))`.

### Chat scroll
16px gap between turns. Padding 14px 12px.

**Analyst message** — right-aligned bubble, max-width 86%, `--he-primary` background, white text,
radius `13px 13px 4px 13px`, `box-shadow: 0 2px 8px rgba(115,113,252,.3)`.
Slash-command variant: `--elevated-2` background, `--selected-border`, mono, command token in
`--he-primary-soft`.

**AI message** — 24px gradient avatar + body column (gap 9px):
eyebrow `reckon · <model>` (10px/700 uppercase, model in `--he-primary-soft`), then tool-call
blocks, optional table, then streamed prose (14px, `line-height: 1.62`).

**Confidence meter** — shield glyph + label + 54×5px bar filled in primary.
e.g. *"2 tools · full coverage"* 100%, *"1 partial source · medium-high"* 76%.

### Composer
- Container: `--elevated`, 1px `--border-strong`, radius 10px. Focused adds `--selected-border`
  + `0 0 0 3px rgba(115,113,252,.14)`.
- Scope line above the input: 10px, green dot + *"scoped to **inv-…**"*. The panel is
  investigation-scoped, never a general chatbot.
- Auto-growing textarea, max 140px.
- Footer: commands (⚡) button · hint `⌘↵ send · ⇧↵ newline` · 30px primary send button.
- Above it, **suggestion chips** — the pending pin (if any) and the next logical question.
  The active one pulses with the `nudge` ring.

### Paused / archived veil
Full-panel overlay `rgba(8,12,28,.6)` + 2px blur, centered pause glyph in warning,
*"Investigation paused / State is preserved exactly — the file and panel restore where you left
off. No session to expire."* + Resume button. Composer disabled.

---

## 2.3 Tool-call block

The trust primitive. Used identically in panel and file.

**Collapsed header** (clickable, 8px 10px): 22px tool logo square (brand color, 2-letter
abbreviation, white 10px/800) · tool name 13px/600 + `operation()` in 11px mono `--text-3` ·
status pill · chevron rotating 90° on open.

**Status sequence** — must animate through all of these, never jump:
| State | Pill | Border |
|---|---|---|
| `calling` | spinner + "Calling <short>" — info | `--info-bd` |
| `received` | spinner + "Received" — info | `--info-bd` |
| `normalizing` | spinner + "Normalizing" — primary | `--info-bd` |
| `done` | check + "Done" — success | `--border` |
| `done` w/ PARTIAL | check + "Partial" — warning | `--border` |
| `error` | alert + "Failed" — danger | `--bad-bd` |
| `skipped` | info + "Skipped" — muted | dashed, opacity .82 |

**Expanded body**, three sections separated by hairlines:
1. **Query sent** — the literal parameters, mono 11px in a `--editor-bg` inset box.
2. **Normalized summary** — prose with live entity chips, plus a coverage pill:
   `FULL` success · `PARTIAL` warning · `NOT_AVAILABLE` muted · `ERROR` danger ·
   `NOT_CONFIGURED` muted.
3. **View raw response** — collapsed link (`--he-primary-soft`); expands to syntax-highlighted
   JSON (keys `--ent-host`, strings `--ent-domain`, numbers `--ent-hash`, booleans `--ent-user`),
   max-height 240px, scrollable.
Footer actions: **Pin as evidence**, **Copy JSON**.

**Fan-out** — when a step calls 2+ tools, precede the group with a divider label
`⟨layers⟩ Federating across N tools`. Fast tools resolve first; a slow tool keeps spinning
independently. **Never block the response on the slowest tool.**

**Inline notes** (not cards) for non-results:
- Not configured — dashed border, info glyph, *"**Proofpoint TAP** is not configured for this
  tenant. Skipped the email vector."* + `Configure` link → settings.
- Error — warning-tinted, tool name, error, `Retry` link.
- "No data" is **information, not failure** — render it plainly, never as an error.

**Result table** — 1px bordered, radius 7px. Header 10px uppercase on `--fill`. Flagged rows get
`--bad-bg` and a 3px inset danger bar on the first cell plus a leading alert glyph.

---

## 2.4 Entity interaction

### Popover (click a chip) — 320px, `--overlay-bg`, radius 10px, `--shadow-pop`
1. Header: 34px type-tinted icon · type label (10px uppercase, type color) · value (14px mono/600)
2. **Deterministic ID (UUIDv5)** — the canonical UUID in 11px mono
3. Alias row when applicable: `jchen@acme.local ⇄ john.chen@acme.local` — linked, **never merged**
4. Cross-investigation list: *"Appears in N other investigations"*, each row with a status dot,
   title, and state; clicking opens it. If none:
   *"First seen in this investigation. Cross-investigation identity is preserved by deterministic
   UUID — not surveillance, just join keys."*
5. 2×2 action grid: **Pivot on entity** (primary), **Pin as evidence**, **Add alias**, **Copy value**

Pivot stages a question in the composer rather than firing immediately.

### Context menu (right-click) — 210px min
View entity details · Pin as evidence · Pivot on entity · ─ · Add alias · Copy value

On selected text in the reasoning trace: Pin as Evidence · Pivot on Entity · Search in Logs · ─ ·
Copy step as markdown.

---

## 2.5 Slash commands

Autocomplete opens on `/` and filters as you type. Popover sits above the composer:
28px icon tile · mono command in `--he-primary-soft` with `<args>` in muted · one-line description.
`↑↓` navigate, `Tab`/`Enter` complete, `Esc` dismiss. Once the command has an argument, the
popover closes and `Enter` submits.

**Core set (always available)**
| Command | Behavior |
|---|---|
| `/verdict <benign\|suspicious\|malicious> — <rationale>` | Opens the verdict confirmation dialog |
| `/status <state>` | Lifecycle transition; validates preconditions |
| `/hypothesis <statement>` | Records a tracked hypothesis (open/supported/refuted) |
| `/pin <finding>` | Pins evidence manually |

Remediation and comms commands are added contextually — see `03` and `04`.

---

## 2.6 Lifecycle

```
DRAFT ──(first AI interaction, implicit)──> ACTIVE
ACTIVE <──> PAUSED
ACTIVE ──(/verdict)──> VERDICT_REACHED
VERDICT_REACHED ──(first action executes)──> REMEDIATING
REMEDIATING ──(all actions + comms terminal)──> CONCLUDED
CONCLUDED ──(reopen)──> ACTIVE
any ──> ARCHIVED   (terminal, read-only)
```

Status must be visible simultaneously in: file header, panel context bar, tree view, and status bar.
`DRAFT → ACTIVE` is implicit and silent-ish (a toast is fine). `CONCLUDED` requires a deliberate
confirmation showing exactly what gets locked.

---

## 2.7 Entry points

**New Investigation** (`⌘⇧I`) — a two-step palette. Step 2 is the seed picker: three cards
(Alert ID / IOC / Hypothesis), a mono input with a type prefix (`alert:`, `ioc:`), and a footer
showing the exact file that will be created:
*"Creates `investigations/2026-04-25_EDR-ALERT-7741.inv.md` and opens the panel."*

**Never** let the analyst start from an empty chat. Entity-rooted entry is load-bearing —
an investigation always begins from something concrete.

Other entries: `⌘⇧O` open (`*.inv.md` picker), `⌘⇧P` all reckon commands, `⌘⇧E` focus composer.

---

## 2.8 Evidence in reach

The trust loop's last step (README non-negotiable #8): every rendered evidence ref opens.
Clicking a cited `observed-data` / OCSF-event ref anywhere — assistant prose, a pin, an
action card's evidence chips, a prediction's test results — opens the underlying record
read-only (raw JSON via a reckon URI in a real editor tab; `design/13 §7` step 6). The
same affordance from the tool-call block's raw view and from the entity popover. An
analyst's trust in the agent is calibrated by spot-checking it; spot-checking is one click.

## 2.9 Hypothesis tracker — the drivable loop

Hypotheses are the unit of work, not passive rail entries. Each hypothesis card renders the
full epistemic state from the engine (statuses verbatim: `PROPOSED / OPEN / SUPPORTED /
REFUTED / INCONCLUSIVE / ABANDONED`) with its **predictions** nested — statement, status
(`UNTESTED / CONFIRMED / DISCONFIRMED / INCONCLUSIVE`), and test-result refs (clickable,
§2.8). Interactions:

- **Acknowledge** on a `PROPOSED` (AI-authored) hypothesis — the human taking ownership
  (engine-enforced human act).
- **Test this** on an `UNTESTED` prediction — stages the prediction's declared test query
  as a composer question (staged, never auto-fired — the pivot pattern).
- The tracker surfaces the **cheapest untested prediction** as the suggested next move:
  the "what would decide this?" question answered at a glance.

The scoreboard framing is the point: what is still open, and what evidence would decide it.

## 2.10 Verdict dialog — preflight and residual

`/verdict` (or the header action) opens a confirmation dialog that renders the engine's
gates as a **preflight checklist** (non-negotiable #7), live before submission:

- ☑/☐ at least one pinned evidence item (unmet → links to the pinned-evidence surface)
- ☑/☐ evidence cited on this verdict (the dialog collects refs)
- rationale field (required)

Below the checklist, the **coverage residual** — what the analyst is signing over:

- Capability verbs `UNAVAILABLE_TENANT` for this investigation ("the email vector was
  never checkable — Proofpoint is not configured")
- Searches that returned `COMPLETE` with zero events (evidence of absence — each pinnable
  as a finding directly from this list)
- Predictions still `UNTESTED`

The residual panel is decision support, not a blocker: the analyst may proceed, but the
record of what was *not* investigated is in front of them at the moment of judgment — and
it is what goes in the postmortem if the verdict was wrong. The conclude dialog reuses the
same checklist pattern (verdict recorded · actions terminal · comms resolved).

## 2.11 Consulted knowledge

When a turn's interpretation carries `consulted_sops` (the schema distinguishes retrieved
from `used`), the turn renders a knowledge chip: *"followed SOP: ransomware-triage §3"*
(used) vs a muted *"consulted, not applied"*. Click opens the SOP. This is the
"it follows our procedures and shows where" surface — provenance the engine already
records, made visible.

## 2.12 Returning to an investigation

Interruption is the norm. On open, if the thread has grown since this analyst last viewed
it, render a **"since you were here" divider** at the first unseen entry (last-seen
position is view state, not investigation state) and a one-line delta in the context bar:
*"+3 reasoning steps · 1 action resulted · 1 approval expiring in 12m"*.

## 2.13 Notifications & empty states

Toasts: 340px, `--overlay-bg`, `--shadow-pop`, 18px semantic glyph, title 13px/600, message 12px
`--text-2`, optional actions in `--he-primary-soft`. Auto-dismiss 4.2s unless actions are present.
Tool failures and coverage gaps are **non-blocking** — inline indicators, never modals.

Empty states to build:
- **No investigations** — welcome view: 76px logo, product line, and keyboard-first action list
  (New / Open / Command Palette / Configure tools), footer *"N of M federated tools connected"*.
- **Investigation with no reasoning** — see § 2.1.
- **Tool not configured** — inline note with Configure link.
