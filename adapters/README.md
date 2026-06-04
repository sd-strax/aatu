# adapters/

First-party adapter binaries. Each subdirectory is its own Go-buildable adapter binary that aatu's capability layer spawns as a separate process and communicates with over JSON-RPC (MCP-compatible transport).

See `design/03-capability-layer.md §5.4` for the adapter contract and class taxonomy (`MCP`, `NATIVE_API`, `CUSTOM`, `FIXTURE`, `SOAR_PLAYBOOK`).

## Status

Empty at Week 1. First inhabitants:

- `fixture/` — Phase B; serves canned OCSF for the v0 design-partner demo
- `mcp-shim/` — Phase B; adapter scaffold for wrapping external MCP servers
- Vendor-specific adapters (EDR, SIEM, IdP, TI, CM) — Phase E

Scaffold new adapters with the `/generate-adapter-scaffold` slash command.
