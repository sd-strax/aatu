# Analyst Workbench — Spec

## 0. Framing

This spec defines the analyst-facing product surface: what runs where (the two-plane split between
the CLI and the VS Code extension), what the extension *is* (a SOC workbench hosted in VS Code,
not an editor with a sidebar), the **workbench discipline** that keeps the distribution question a
packaging decision, and the surface inventory with its v0 slice. It is the first UX-side spec; the
architecture it renders is owned elsewhere and unchanged by it.

The one-sentence summary: **the CLI owns the operator/author plane, the extension owns the analyst
plane, every analyst surface lives in reckon-owned real estate, and the choice between "extension
in stock VS Code" and "trimmed custom distribution" is deliberately reduced to packaging.**

| Owned here (`13`) | Owned elsewhere (authoritative) |
|---|---|
| The two-plane split (CLI vs. extension) and the substrate decision | Interactive-loop mechanics, BYOK, turn commit (`05 §3.4`) |
| The workbench discipline and the profile trim | Authorization semantics the approval surfaces render (`04`) |
| The surface inventory, panel homes, and the v0 slice | Conversational enablement rules the config widgets implement (`11 §5.1`, `§4.3`) |
| Investigation-first / editor-in-reach posture | Agent behavior and prompt ownership (`09`) |
| Fork-as-packaging: the framed deferral and its criteria | The async approval web surface (`05 §4.4`, `§11.3`) |

### Out of scope

- **Visual design.** Layout sketches, component libraries, styling, interaction details. This spec
  fixes which surfaces exist, where they live, and what rules bind them — not what they look like.
- **The agent loop.** `05 §3.4` owns the interactive-turn mechanics (BYOK in the OS keychain,
  direct-to-provider LLM calls, tool dispatch to the backend, transcript commit). The extension is
  that design's host, not its owner.
- **The async approval surface.** Approvals that arrive by email/chat deep link land on the
  reckon-operated web surface (`05 §11.3`), not in the extension. The extension renders the
  synchronous, analyst-present approval flows.
- **Multi-analyst presence and shared-investigation UX** (`05 §8`) — SaaS-tier; the surface
  inventory reserves homes for it, the design is deferred with it.

---

## 1. The two-plane split

Two user-facing programs, one engine, no duplication:

**The CLI owns the operator/author plane.** It exists already and grew organically in that shape:
supervisor lifecycle (`start`/`stop`/`status`/`check`), adapter authoring (`adapter scaffold`,
`adapter test` — `12 §7`), adapter operation (`adapter install`, `adapter enable` — `12 §5`,
`11 §5`), and diagnostics (`reckon check` as the config/health oracle). This plane is
CLI-shaped for load-bearing reasons: scriptable, CI-runnable, airgap-friendly, and diffable
against version-controlled tenant config. None of it belongs in a chat panel.

**The extension owns the analyst plane**: investigations, the reasoning thread, evidence, approvals,
knowledge — the surfaces in `§4`. This plane is visual for equally load-bearing reasons: the
two-layer graph, the timeline, and the approval flows (typed challenges, blast-radius display)
have no honest terminal rendering.

**A conversational analyst CLI is a deferral, not a rejection.** The agent loop (`agent.Session`)
is substrate-neutral — the eval harness (`10`) already drives it headlessly. A terminal analyst
surface later is packaging around the existing loop, not a second implementation. It stays
deferred until a real audience asks for it; nothing in this spec makes it harder.

The planes meet in exactly one place: `11 §5.1`'s conversational enablement, where an
analyst-plane conversation surfaces an operator-plane act. The seam holds there because the
extension widget writes the same tenant config the CLI writes, under the same
human-confirm-and-record rules — the plane split is about *default homes*, not walls.

---

## 2. The substrate decision

The options span a spectrum: bare extension in stock VS Code → extension plus a managed profile →
a custom VS Code-derived distribution → a fully custom shell. The decision:

**v0 ships an extension plus a managed profile. A custom distribution is explicitly anticipated,
deliberately deferred, and — by the discipline in `§3` — reduced to a packaging decision.**

Why not a bare extension: stock VS Code's default posture is a developer workbench — file
explorer, source control, run-and-debug, task runner, extension marketplace. For an analyst who
is not living in VS Code already, that chrome is noise at best and misdirection at worst
("which of these buttons is the product?"). The managed profile (`§6`) trims most of it.

Why not fork now: a custom distribution is a permanent tax paid immediately — tracking upstream
releases, build/sign/notarize/update infrastructure per OS, marketplace licensing (the official
extension marketplace serves official builds only; forks use OpenVSX), and ownership of the
Electron security-patch cadence, which for a security product is not a footnote. Paying that tax
before a single analyst has used the graph view buys chrome removal and nothing else. The profile
gets ~80% of the trim for ~2% of the cost.

Why the fork stays on the map: profile trimming has a ceiling (`§6`) — native menus, window
title, product branding, and marketplace exposure are `product.json`-level controls an extension
cannot reach. A purpose-built SOC workbench eventually wants them.

**The criteria for flipping** (recorded now so the later decision is a check, not a debate): the
trim ceiling is demonstrably hurting analysts (observed confusion attributable to residual
chrome, not missing features); the extension's surfaces are stable enough that upstream-tracking
cost is amortizable; and distribution logistics (signing, updates) have an owner. Absent those,
the profile posture stands.

**Residence and packaging.** The extension lives in the engine repo as `workbench/`
(`implementation/module-layout.md` has the full rationale): its contract is the backend HTTP API,
which churns with every `§7` step, so one repo keeps server and surface in atomic commits. It
ships as its own artifact — a `.vsix` with its own version — on three channels: the VS Code
Marketplace, OpenVSX from day one (the trimmed distribution above can only consume OpenVSX;
early dual-publishing is what keeps "fork = packaging" true), and release-attached for airgapped
sideload. The extension never bundles the engine — it talks to a locally running backend and
asserts a compatible version at the `/status` handshake, failing closed with a diagnostic on
mismatch.

---

## 3. The workbench discipline

The rule that makes `§2`'s deferral safe — load-bearing, alongside the architectural commitments:

> **Every reckon surface lives in reckon-owned real estate — the reckon view container, reckon
> custom editors and webviews, reckon panels, reckon walkthroughs — and no reckon feature
> depends on, extends, or assumes stock chrome.** Nothing hangs off the file explorer, the SCM
> view, the debug surface, or a native menu. If a surface needs a home, it gets a reckon home.

Consequences, spelled out:

- **No workspace-folder assumption.** An investigation is not a directory. The extension must be
  fully functional in an empty window with no folder open; investigation state comes from the
  backend, not the filesystem. (Exports and evidence files *may* be written to disk on request —
  that is a feature, not a dependency.)
- **Custom editors, not file conventions.** The investigation document, the graph, the timeline
  are custom editors/webviews addressed by reckon URIs — never "a JSON file the extension
  decorates," which would re-import the editor posture through the back door.
- **Commands over menus.** Every reckon action is a contributed command (palette-discoverable,
  keybindable); menu/toolbar placements are conveniences layered on commands, never the only
  path. This is also what makes the profile trim (`§6`) safe — hiding chrome can't orphan a
  feature.
- **The fork test.** A change is discipline-compliant iff it would survive relocation into a
  trimmed distribution with stock chrome absent. Anything that fails the test is re-homed now,
  not at fork time.

---

## 4. Surface inventory

The homes, mapped to the specs that own their semantics. The `00-summary` "Open for UX work"
list is the superset; this inventory assigns each surface a home and a phase. **v0** = the
fixture-scenario walking skeleton; **v1** = live-tenant hardening; **SaaS** = tenancy-gated.

**The reckon view container** (one activity-bar entry — the product's front door):

| Surface | What it is | Semantics | Phase |
|---|---|---|---|
| Investigation list | Open/recent investigations, lifecycle state, seed summary | `01` | v0 |
| Seed entry | Start an investigation (entity-rooted) or hunt (hypothesis-rooted) | `01` | v0 |
| Pending approvals | Actions awaiting this analyst, presence-aware later | `04 §5` | v0 |
| Capability health | Verbs/actions available–degraded–unavailable; installed-not-enabled (operator view) | `03 §6.3`, `11 §6.2` | v0 |
| SOP library | Browse/filter; editor + review queue later | `06` | v1 |

**The investigation document** (custom editor, the primary workspace):

| Surface | What it is | Semantics | Phase |
|---|---|---|---|
| Conversation + reasoning thread | The turn loop; interpretations chronological, branching, foldable, with rationale and cited evidence | `05 §3.4`, `09`, `01` | v0 |
| Inline approval flow | T2 single-confirm (verb + targets + evidence + approve/reject); T3 typed challenge; two-party | `04 §5` | v0 (T2/T3), SaaS (two-party) |
| Enablement widgets | Schema-derived config forms, secret-backend chooser, gap-closure hints | `11 §5.1`, `§4.3` | v0 |
| Evidence graph | Two-layer view: interpretation objects joined to telemetry, typed edges explicit | `01` | v0 (minimal), v1 (rich) |
| Timeline | Event-time ordering of observed data across sources | `01`, `02` | v1 |
| Pivot panels | Entity context, indicator context, similar investigations | `03 §2`, `06 §4` | v1 |
| Conclusion flow | ConclusionSlot rendering; export/post-conclusion handoff | `01`, `07` | v1 |

**Deliberately elsewhere:** async approval landing (web, `05 §11.3`); operator/author flows
(CLI, `§1`); tenant admin console (SaaS, `05 §4`); dashboards and export viewers (`07`; phase
with their specs).

Two inventory-wide rules. First, the approval surfaces render decisions they never make —
`04`'s gates are engine-side, and the extension's approve button is a signed command carrying
the human principal, exactly as the endpoint contract requires (JWT-derived actor, `04`,
`08 §2`). Second, `11 §6.2`'s visibility split is honored in the UI: the *capability health*
panel (operator-facing) shows installed-not-enabled; the *agent's* tool surface never does —
the hint channel is the only bridge, and it is mentionable, not actionable.

---

## 5. Investigation-first, editor-in-reach

The product's audience — threat hunters and IR responders, not tiered triage — is part of why a
VS Code host is a feature and not baggage. The posture has two halves, and both are deliberate:

**Investigation-first.** The landing experience is the reckon container and the investigation
document. No file explorer as home base, no startup editor, no developer-workflow affordances in
the default posture (`§6` trims run-and-debug, SCM, tasks, marketplace from view).

**Editor-in-reach.** The full editor remains one command away, because for this audience it is
part of the job: open a piece of raw OCSF evidence as real JSON (via a reckon read-only URI, not
a workspace file); draft a detection rule or query in a scratch editor next to the conversation;
keep a notebook beside the investigation. The workbench never *removes* text editing — it
removes text editing as the *identity* of the product. What gets trimmed is the developer
workflow chrome, not the editing capability.

The line between the halves is the discipline (`§3`): reckon surfaces never depend on the editor
posture; the editor posture never intrudes on the landing experience.

---

## 6. The profile trim

The managed profile is the mechanism that makes stock VS Code present as a workbench. VS Code
profiles bundle settings, keybindings, UI state, and an extension set; the reckon extension
ships one and offers it on first run — offered, never forced (an analyst embedding reckon in
their existing developer profile is a supported choice; the discipline guarantees nothing breaks
there, `§3`).

What the profile sets (indicative, not exhaustive; exact keys tracked in the extension repo as
they evolve with upstream):

- Activity bar reduced to the reckon container (+ search); explorer, SCM, run-and-debug, and
  extensions views hidden from the default posture.
- Menu bar hidden (native affordances remain per-OS conventions); status bar reduced to
  reckon-relevant items; no startup editor; reckon walkthrough as the first-run surface.
- Panel/layout defaults arranged for the investigation document; workspace-trust and telemetry
  prompts pre-answered where policy allows.
- Keybindings for the core loop (new investigation, approve/review focus, open raw evidence,
  toggle graph).

**The ceiling, stated honestly:** an extension + profile cannot remove native menus (only hide
the bar), cannot rebrand the window or product identity, cannot prevent a user from reopening
hidden views or the marketplace, and cannot alter `product.json`-level behavior. Everything
above the ceiling is the fork's exclusive payoff (`§2`); everything below it, the profile owns.
The trim is a posture, not a jail — analysts can undo any of it, and the product must stay
coherent when they do (discipline, again).

---

## 7. The v0 slice

The walking skeleton, in dependency order — each step usable against the shipped fixture
scenario (`fixtures/lateral-movement-via-rdp/`, `03 §9`) with no live tenant:

1. **Session + auth**: PKCE against local Keycloak, BYOK key into the OS keychain, capability
   descriptors fetched and trimmed per `05 §3.4`.
2. **Investigation list + seed entry** in the reckon container; investigation document opens as
   a custom editor.
3. **The conversation**: interactive turns, tool dispatch, streaming; reasoning thread rendered
   chronologically with foldable interpretations and cited evidence; transcript commit per
   `05 §3.4` (the same committed turn record the eval harness grades, `10 §3` — one behavior,
   two consumers).
4. **Approvals inline**: T2 single-confirm and T3 typed-challenge against the real Gate 2 path
   (`04 §4`–`§5`, `server/actions.go`).
5. **Enablement widgets**: the `11 §5.1` flow end-to-end — gap hint, schema-derived form,
   human confirm, recorded event, secret capture out-of-band.
6. **Raw evidence in reach**: read-only OCSF JSON via reckon URIs from any cited evidence ref.
7. **Minimal graph**: the two-layer join rendered navigably (interpretation → evidence →
   telemetry); richness deferred to v1.
8. **The profile** (`§6`) wrapping the above.

Explicitly not in v0: timeline, pivot panels, SOP surfaces beyond recall-in-conversation,
conclusion/export flow, presence, dashboards. The slice is judged by one test: an analyst can
run the fixture investigation end-to-end — seed to evidence-grounded action approval — without
touching a terminal or a YAML file.

---

## 8. Open questions / deferred to v1+

- **Webview architecture.** One webview hosting the whole investigation document vs. composed
  native views + focused webviews (graph, timeline). Leans composed — native views inherit
  theming/accessibility/context-keys for free and keep state smaller per surface — but the
  graph's needs may force the decision; settle at implementation.
- **State synchronization.** How the extension observes aggregate changes it didn't cause
  (another window, CLI, async workflow): SSE/WebSocket push vs. focus-triggered re-fetch at v0.
  The aggregate's event stream (`02`) is the natural push source; the wire is undecided.
- **Offline/degraded posture.** What the workbench does when the backend is unreachable —
  read-only cached view vs. hard gate. Leans hard-gate-with-diagnostics at v0 (no local cache
  invents a second source of truth); revisit with real usage.
- **Scratch artifacts.** Where analyst drafts (queries, notes, detection sketches) live —
  ephemeral editors, a reckon scratch area attached to the investigation, or the user's own
  files. Touches `01` (is a note evidence?) — deferred until the conclusion flow forces it.
- **The conversational CLI** (`§1`) — deferred until asked for; `agent.Session` keeps it cheap.
- **Fork trigger review.** The `§2` criteria are recorded; revisit them once the v0 slice has
  real analyst hours on it.

---

*End of spec. The loop this workbench hosts is `05 §3.4`; the behavior of the agent inside it is
`09`; the enablement flow it renders is `11 §5.1`; the approval semantics it renders are `04`;
what it grades against is `10`.*
