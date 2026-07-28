# design/ui — workbench UI specifications

The visual and interaction specs for the analyst workbench: multiple documents
describing the UI surfaces under a top-down architecture model. Entry point is
`00-architecture.md` (the shared vocabulary and the model the per-surface docs
hang off), then one numbered document per surface.

## How this subtree relates to the rest of `design/`

- **`design/13-workbench.md` stays authoritative for *what exists*.** The
  surface inventory and phasing (`13 §4`), the workbench discipline (`13 §3`),
  and the substrate decision (`13 §2`) are owned there. Documents here own
  *how surfaces look and behave*. A surface described here that is not in
  `13 §4`'s inventory is a scope change to make in `13` first, not a silent
  fork.
- **Cross-references point out of this subtree, never into it.** UI docs cite
  engine specs by section (`03 §6.3` capability health, `04 §5` approvals,
  `01` reasoning primitives) and name the endpoints that feed each element.
  Engine specs never depend on UI docs.
- **Every rendered element names its data source.** An element with no serving
  endpoint or spec section is a flagged gap, not an implication that one
  exists — gaps go in the doc's "Open questions" section.

## Conventions

Same as the top-level specs: framing/scope → out-of-scope → numbered sections
→ end-of-spec marker; cross-reference by section number. Same public-OSS
posture as everything in this repo: architectural and design facts only — no
team-shape framing, no design-review provenance (see `CLAUDE.md`).
