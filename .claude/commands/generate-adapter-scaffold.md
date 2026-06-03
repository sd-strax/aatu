---
description: Scaffold a new JSON-RPC adapter under adapters/
---

Given an adapter name (e.g., `crowdstrike`, `okta`, `splunk`, `tines`), create `adapters/<name>/` with:

- `main.go` — minimal JSON-RPC server (stdio transport, MCP-compatible) with one stub method: `list_capabilities` returning an empty `[]Capability`.
- `manifest.yaml` — adapter manifest declaring `name`, `version`, `class` (one of `MCP`/`NATIVE_API`/`CUSTOM`/`FIXTURE`/`SOAR_PLAYBOOK`), and empty `capabilities:` block. See `design/03-capability-layer.md §5.4` for the canonical schema.
- `README.md` — what this adapter wraps; auth model; eventual capability set; current state (scaffold).
- `main_test.go` — start the binary, send a `list_capabilities` JSON-RPC request, assert a valid response shape.

The scaffold compiles, runs, and answers `list_capabilities` with an empty list. Real verbs land per-adapter as the integration matures.

Ask for the adapter name and class before generating. Default class to `NATIVE_API` if unstated.
