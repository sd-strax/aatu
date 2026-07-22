# reckon workbench

The analyst-facing VS Code extension — the primary product surface. The design is
[`design/13-workbench.md`](../design/13-workbench.md); residence and packaging rationale is in
[`implementation/module-layout.md`](../implementation/module-layout.md) ("The workbench").

## Current state

Scaffold: the reckon view container, an Investigations placeholder view, the
`reckon.checkBackend` / `reckon.refreshInvestigations` commands, and a thin `/status` client.
The v0 slice lands in the order of `design/13 §7` (session/auth next).

## Development

```bash
npm ci              # or: make workbench-ci from the repo root (install + compile)
npm run compile     # tsc → out/
npm run watch
```

Open **this folder** (not the repo root) in VS Code and press F5 → *Run Workbench Extension*. The
default config launches the Extension Development Host with `--disable-extensions`, so only reckon
loads: what you see is what an analyst gets, and your own extensions don't react to this folder
(a C# extension hunting for a project in `workbench/` is the classic false alarm). The second
config keeps your extensions if you need them.

In the dev host: the reckon icon in the activity bar → **Investigations**. Activation is logged
to the **reckon** output channel; `reckon: Check Backend Connection` is in the command palette.

The extension expects a locally running backend (`reckon start` from a built repo, or the release
bundle); without one, every surface degrades to "not connected" with a pointer — never a crash
(fail closed with a diagnostic, the house posture).

## Rules that bind this package

- **Workbench discipline** (`design/13 §3`): every surface in reckon-owned real estate; commands
  over menus; no workspace-folder assumption — an investigation is not a directory.
- **No engine in the artifact**: the `.vsix` never bundles the backend; the engine ships via
  `make bundle`.
- **Zero paid awareness**: paid capability lights up server-side behind `module/` interfaces;
  this extension renders what the backend serves.
- **Publish targets**: VS Code Marketplace + OpenVSX (both, from the first release — see
  `design/13 §2` on why OpenVSX is non-optional), plus release-attached `.vsix` for airgapped
  sideload. Publisher id `reckon` is a placeholder until the marketplace account exists.

## Pending backend seams

- `/status` has no version field yet; the `design/13 §2` version handshake (assert compatible
  backend version, fail closed on mismatch) lands with the session/auth step.
