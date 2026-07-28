# design/ui — Workbench UI Specification

The complete UX/design specification for the **reckon VS Code workbench**: an AI-native SOC
investigation environment. It covers the full lifecycle — alert → investigation → federated
enrichment → verdict → remediation → coordination → closure.

**Read `00-backend-binding.md` first.** It is the authority layer over this package: the
sheets specify how surfaces look and behave; the binding specifies what feeds every element
and which engine vocabulary it speaks. Where a sheet and the binding disagree, the binding
wins — the engine's data model wins in all respects in the UI.

The package originated as a high-fidelity standalone prototype (since removed — the specs
are the distillation and stand alone). Fidelity is final: colors, typography, spacing,
radii, motion, and component states are specified exactly in `01-design-system.md`,
expressed through VS Code theme variables where noted.

## Read in this order

| File | Contents |
|---|---|
| `00-backend-binding.md` | **The authority layer** — engine bindings, vocabularies, gaps, open questions |
| `01-design-system.md` | Tokens: color, type, spacing, radius, motion, entity palette, theming |
| `02-investigation-core.md` | Investigation document rendering, Investigation Panel, tool calls, entities, slash commands, lifecycle |
| `03-remediation.md` | Action cards, trust tiers, approval flows, plan block, closure |
| `04-comms.md` | Comms cards, replies, follow-ups, escalation, incident channel (Phase F — binding §4) |
| `05-data-model.md` | State shapes and the reference scenario (data authority: binding §2) |
| `06-vscode-surface-map.md` | Which surface is webview vs native API; commands, keybindings, contributions |
| `07-build-order.md` | Implementation sequence with acceptance criteria |
| `impl-spec/` | Engineering layer: process boundaries, state ownership, event contracts |

## Non-negotiables (the design fails without these)

1. **The record is the engine's.** The event-sourced aggregate is the source of truth; every
   surface renders it. The portable markdown artifact is a backend-rendered export
   (binding §1).
2. **Everything streams.** Tokens, tool-call status transitions, and document growth render
   incrementally. p50 to first token < 3s. Never a spinner over a blank panel.
3. **Tool calls are never a black box.** Tool name, exact query, normalized summary, coverage
   signal, and raw JSON are always one click away.
4. **Nothing executes without explicit approval.** T2 requires confirm; T3 requires the typed
   challenge; two-party is a policy-assigned mode (binding §2.5). Comms require a mandatory
   pre-send preview.
5. **Analyst contributions are sacred.** Analyst-authored acts enter the record as attributed
   events and are never overwritten by the AI.
6. **Verdict is the midpoint, not the end.** The investigation stays open through remediation
   and coordination until every action and comms thread reaches a terminal state.

## Seam rules

- `design/13-workbench.md` stays authoritative for *what exists* (surface inventory, phasing,
  workbench discipline). Sheets here own how surfaces look and behave; a surface not in
  `13 §4` is a scope change to make there first.
- Cross-references point out of this subtree (engine specs, endpoints), never into it.
- Every rendered element names its data source; an element with none is a flagged gap in
  `00-backend-binding.md §6`, not an implication that one exists.
