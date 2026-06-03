---
description: Confirm OSS code does not import from aatu-enterprise
---

Grep all Go files under this repo (excluding `vendor/`) for import paths matching `github.com/sd-strax/aatu-enterprise`. If any are found, list them with `file:line` — this is an architectural violation of the open-core seam.

The contract:
- Paid layers on OSS. OSS has zero awareness of paid.
- The repo boundary is the enforcement. OSS literally cannot reach into paid because paid is not in its import graph.

If a paid-related need surfaces, the answer is to extend `module/` interfaces (in OSS), not to import paid here. See `implementation/module-layout.md` "Paid is layered on OSS, never overlapping."

Exit non-zero on any violation. Useful as a CI check.
