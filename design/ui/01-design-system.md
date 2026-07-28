# 01 — Design System

Every value below is final — this sheet is the source of truth for the token set.

## Typography

| Role | Stack |
|---|---|
| Sans (UI, prose) | `"Open Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif` |
| Mono (all data) | `"JetBrains Mono", source-code-pro, Menlo, Monaco, Consolas, monospace` |

**Rule:** every entity value, ID, timestamp, query, hash, hostname, and raw payload renders in
mono. Prose, labels, and headings render in sans. This split is load-bearing for the audience.

### Scale
| Token | px | Used for |
|---|---|---|
| `--fs-xs` | 11 | metadata, tree meta, captions |
| `--fs-sm` | 12 | secondary text, table cells |
| `--fs-base` | 13 | default UI text, card body |
| `--fs-md` | 14 | file body copy, chat messages |
| `--fs-lg` | 16 | section titles, dialog titles |
| `--fs-xl` | 20 | file H2, frontmatter title |
| `--fs-2xl` | 26 | settings H1, welcome |

Weights: 400 regular, 600 semibold, 700 bold, 800 for tier/state pills.
Micro-labels (uppercase eyebrows) are 9–10px, weight 700, `letter-spacing: .06–.08em`.

## Spacing

4px base: `--sp-1:4 --sp-2:8 --sp-3:12 --sp-4:16 --sp-5:20 --sp-6:24 --sp-8:32 --sp-10:40`

**Density target: Bloomberg Terminal, not Apple.** Card padding 9–11px, row heights 24–38px,
gaps 6–10px. Dense but structured — never cramped, never airy.

## Radius

`--r-xs:3 --r-sm:5 --r:7 --r-lg:10 --r-pill:999`

## Motion

```
--dur-fast: .16s   hover, focus, small toggles
--dur:      .28s   card state changes, expansion
--dur-slow: .55s   entrance animations

--ease:     cubic-bezier(.4, 0, .2, 1)     standard
--ease-out: cubic-bezier(.16, 1, .3, 1)    entrances (popovers, cards, dialogs)
```

Named animations to reproduce:
| Name | Spec |
|---|---|
| Entity pin | `pinIn` — 0.5s ease-out, `translateY(-6px) scale(.98)` → rest, opacity 0→1 |
| Popover / menu | `popIn` — 0.16s ease-out, `translateY(5px) scale(.98)` → rest |
| Dialog | `dlgIn` — 0.2s ease-out, `translate(-50%,-46%) scale(.97)` → centered |
| Command palette | `cmdDrop` — 0.22s ease-out, slides down 14px from top edge |
| Toast | `toastIn` 0.3s ease-out from `translateX(20px)`; `toastOut` reverses |
| Streaming caret | `▍` in `--he-primary-soft`, 1s `steps(2)` blink |
| Spinner | 0.7s linear infinite rotate; 10px circle, 1.6px border, transparent top |
| Health pulse | 2.4s ease infinite, opacity 1 → .4 → 1 |
| Suggestion nudge | 2.4s, box-shadow ring 0 → 4px `rgba(115,113,252,.14)` → 0 |

Streaming text renders **word-by-word**, 1–2 words per tick, 24–50ms jittered interval. Do not
render character-by-character (too slow) or paragraph-at-once (kills perceived latency).

## Brand

```
--he-primary:      #7371fc   reckon indigo — primary actions, active states, AI identity
--he-primary-soft: #8b8aff   links, inline emphasis on dark
--he-primary-deep: #5d5be0   hover/pressed, status bar background
--he-secondary:    #b06bd6   AI avatar gradient endpoint
--he-teal:         #2bb6e6   accent, logo mark
```
AI avatar: `linear-gradient(135deg, #7371fc, #b06bd6)`, 24px, radius 7px.

## Dark theme (primary)

### Surfaces — a deep navy ramp, not neutral gray
```
--titlebar-bg:    #070b1c
--activity-bg:    #080d20
--sidebar-bg:     #0a0f24
--editor-bg:      #0a0f24
--panel-bg:       #0c1228
--elevated:       #141a33    cards, tool-call blocks
--elevated-2:     #1a2142    nested/raised
--overlay-bg:     #11172f    popovers, dialogs, menus
--statusbar-bg:   #5d5be0    indigo; becomes #1f2547 when concluded
```

### Text & lines
```
--text:     rgba(255,255,255,.88)
--text-2:   rgba(255,255,255,.62)
--text-3:   rgba(255,255,255,.40)
--text-4:   rgba(255,255,255,.26)

--border:          rgba(255,255,255,.09)
--border-2:        rgba(255,255,255,.05)
--border-strong:   rgba(255,255,255,.16)

--fill:      rgba(255,255,255,.05)
--fill-2:    rgba(255,255,255,.08)
--fill-3:    rgba(255,255,255,.12)
--hover:     rgba(255,255,255,.055)
--selected:        rgba(115,113,252,.16)
--selected-border: rgba(115,113,252,.45)
```

### Semantic
| Role | Text | Background | Border |
|---|---|---|---|
| Success / benign / healthy | `#4ec77b` | `rgba(78,199,123,.13)` | `rgba(78,199,123,.32)` |
| Warning / suspicious / partial | `#f5b53d` | `rgba(245,181,61,.13)` | `rgba(245,181,61,.34)` |
| Danger / malicious / failed | `#ff5f6e` | `rgba(255,95,110,.13)` | `rgba(255,95,110,.34)` |
| Info / in-progress | `#4aa8ff` | `rgba(74,168,255,.13)` | `rgba(74,168,255,.34)` |

Evidence pin accent: `--pin: #f5b53d` (amber, same family as warning).

### Shadows
```
--shadow-pop:   0 12px 40px rgba(0,0,0,.55), 0 2px 8px rgba(0,0,0,.4)
--shadow-panel: 0 8px 28px rgba(0,0,0,.45)
```

## Entity-type palette

Each entity type has a fixed color used **consistently everywhere** — file, panel, tables,
popovers, tree. This is a core comprehension aid; do not vary it by context.

| Type | Dark | Dark bg | Light | Light bg |
|---|---|---|---|---|
| `host` | `#6fb6f2` | `rgba(111,182,242,.14)` | `#1f6fc4` | `rgba(31,111,196,.10)` |
| `user-account` | `#c98fe0` | `rgba(201,143,224,.15)` | `#9333b8` | `rgba(147,51,184,.10)` |
| `ipv4-addr` | `#45c9d6` | `rgba(69,201,214,.14)` | `#0e8a9c` | `rgba(14,138,156,.10)` |
| `file-hash` | `#f0b94c` | `rgba(240,185,76,.14)` | `#b3790a` | `rgba(179,121,10,.11)` |
| `domain` | `#6fd698` | `rgba(111,214,152,.14)` | `#1c9b57` | `rgba(28,155,87,.10)` |
| `email-addr` | `#a99bf5` | `rgba(169,155,245,.15)` | `#6a5be0` | `rgba(106,91,224,.10)` |
| `process` | `#b6c2cf` | `rgba(182,194,207,.13)` | `#5a6b7b` | `rgba(90,107,123,.10)` |
| `alert` | `#f59a6b` | `rgba(245,154,107,.14)` | `#d2671f` | `rgba(210,103,31,.10)` |

### Entity chip anatomy
```
display: inline-flex; gap: 4px; align-items: center;
font-family: mono; font-size: .92em; font-weight: 600;
padding: 1px 7px 1px 6px; border-radius: 5px; line-height: 1.45;
color: <type color>; background: <type bg>;
```
- Leading 6×6px square swatch (`border-radius: 2px`) in the type color.
- Hover: `filter: brightness(1.18)` + `box-shadow: 0 0 0 1px currentColor inset`.
- Pinned: persistent `box-shadow: 0 0 0 1px var(--pin) inset` + trailing 11px pin glyph in amber.
- Click → entity popover. Right-click → entity context menu.

## Light theme (tested secondary)

```
--titlebar-bg: #e8e8ec   --activity-bg: #f3f3f5   --sidebar-bg: #f6f6f8
--editor-bg:   #ffffff   --panel-bg:    #f6f6f8   --elevated:    #ffffff
--elevated-2:  #f1f1f5   --overlay-bg:  #ffffff   --statusbar-bg:#5d5be0

--text:   rgba(13,17,36,.90)   --text-2: rgba(13,17,36,.62)
--text-3: rgba(13,17,36,.42)   --text-4: rgba(13,17,36,.28)
--border: rgba(13,17,36,.12)   --border-2: rgba(13,17,36,.07)
--border-strong: rgba(13,17,36,.20)

ok #1f9d52 · warn #c8860b · bad #e0394a · info #1f7fe0 · pin #c8860b
```

## Theming against VS Code

The palette above is absolute. In the real webview, **prefer VS Code theme variables** for
chrome-adjacent surfaces so the panel doesn't fight the user's theme:

| Use VS Code var | For |
|---|---|
| `--vscode-editor-background` | panel/editor backgrounds |
| `--vscode-foreground`, `--vscode-descriptionForeground` | body / secondary text |
| `--vscode-panel-border`, `--vscode-widget-border` | dividers |
| `--vscode-list-hoverBackground`, `--vscode-list-activeSelectionBackground` | rows |
| `--vscode-input-background/border` | inputs |
| `--vscode-font-family`, `--vscode-editor-font-family` | sans / mono |

**Keep reckon's own tokens** for anything semantic and product-specific — the indigo primary, the
entity palette, trust-tier colors, and action/coverage states. Those must stay stable across
themes because analysts learn them as meaning, not decoration.

Recommended: emit reckon tokens as CSS custom properties on `:root`, and derive only the
chrome-adjacent ones from `--vscode-*`, with the values above as fallbacks.

## Layout metrics

| Element | Size |
|---|---|
| Title bar | 34px |
| Activity bar | 50px wide; items 50×46px; active 2px left indicator in primary |
| Sidebar / tree | 300px wide; header 35px; rows min 38px |
| Editor tab strip | 36px; tabs min 130 / max 240px; active 2px top border in primary |
| Investigation Panel | 446px wide |
| Status bar | 24px |
| File content column | max-width 860px, padding 26px 40px 120px |

Scrollbars: 11px, thumb `rgba(255,255,255,.13)` with 3px transparent border, fully rounded.
