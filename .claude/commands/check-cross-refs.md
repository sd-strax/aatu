---
description: Validate inter-spec cross-references in design/
---

Scan every markdown file under `design/`. For each reference of the form `<file>.md §N.M` or bare `§N.M`, verify the target section exists:

1. `<file>.md §N.M` — open the target file, search for `## N.` (top-level) or `### N.M` (sub-section). Report missing or moved sections.
2. Bare `§N.M` (no file prefix) — assumed to refer to the current file. Same check.

Output:
- List broken cross-references with source `file:line` → expected target.
- Summarize valid references (count only; don't enumerate).
- Don't modify anything — read-only check.

Useful after a spec edit that renumbers sections.
