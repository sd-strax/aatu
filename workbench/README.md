# reckon workbench

The analyst-facing VS Code extension — the primary product surface. The design is
[`design/13-workbench.md`](../design/13-workbench.md); residence and packaging rationale is in
[`implementation/module-layout.md`](../implementation/module-layout.md) ("The workbench").

## Current state

v0 slice (`design/13 §7`) through step 1:

- **Version handshake** (`§2`): fail closed on an incompatible/unreachable backend.
- **Sign in** (`reckon.signIn`): OIDC authorization-code + PKCE against the bundled Keycloak —
  the browser opens, a loopback listener catches the redirect, tokens land in
  `vscode.SecretStorage`, and a background timer refreshes before expiry. `reckon.signOut` clears
  them. Config (issuer + client) is discovered from `/api/auth-config`, not hardcoded.
- **BYOK Anthropic key** (`reckon.setAnthropicKey`): stored in `SecretStorage`, never in settings.
- **Investigations view**: the real list from `/api/investigations` when signed in; a sign-in
  affordance when not; a diagnostic when the backend is incompatible.

Next (`§7`): the investigation document — the conversation surface — as a custom editor, plus the
capability-descriptor fetch feeding the agent's tool definitions.

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

## Backend contract

- **Version handshake** (`design/13 §2`): `/status` carries `api_version` (`server.APIVersion`);
  the extension pins `SUPPORTED_API_VERSIONS` (`src/backend.ts`) and fails closed with a
  diagnostic on mismatch, absence, or unreachability — it never dispatches against an
  incompatible surface.

## Pending backend seams

- **Capability descriptors → LLM tool definitions**: `capabilityCount()` proves the authenticated
  fetch; the agent loop that turns descriptors into tools lands with the conversation surface.
- **The interactive turn loop** (`05 §3.4`): BYOK LLM call → tool dispatch to the backend →
  transcript commit to `/api/interpretations`.
