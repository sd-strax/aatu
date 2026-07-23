# reckon workbench

The analyst-facing VS Code extension — the primary product surface. The design is
[`design/13-workbench.md`](../design/13-workbench.md); residence and packaging rationale is in
[`implementation/module-layout.md`](../implementation/module-layout.md) ("The workbench").

## Current state

v0 slice (`design/13 §7`) through step 2:

- **Version handshake** (`§2`): fail closed on an incompatible/unreachable backend.
- **Sign in** (`reckon.signIn`): OIDC authorization-code + PKCE against the bundled Keycloak —
  the browser opens, a loopback listener catches the redirect, tokens land in
  `vscode.SecretStorage`, and a background timer refreshes before expiry. `reckon.signOut` clears
  them. Config (issuer + client) is discovered from `/api/auth-config`, not hardcoded.
- **BYOK Anthropic key** (`reckon.setAnthropicKey`): stored in `SecretStorage`, never in settings.
- **Investigations view**: the real list from `/api/investigations` when signed in; a sign-in
  affordance when not; a diagnostic when the backend is incompatible.
- **Seed entry** (`reckon.newInvestigation`, the `+` in the view title): titles a new
  investigation via `POST /api/investigations`, refreshes the list, and opens the new document.
- **Investigation document** (`src/investigationDocument.ts`): clicking a row opens a
  reckon-owned webview panel (deduped by investigation id) that renders the reasoning thread
  (header + hypotheses/predictions) and hosts the conversation. The extension host holds the
  token and does every fetch; the webview is a pure renderer under a strict CSP (no network,
  nonce'd script).
- **The interactive turn loop** (`src/agent.ts`, `§7 step 3`, `05 §3.4`): the analyst types, the
  BYOK Anthropic call streams (adaptive thinking, model from \`reckon.model\`, default
  \`claude-opus-4-8\`), read tools are built from the tenant's *available* capability descriptors
  (`GET /api/capabilities`) and dispatched to `POST /api/capability/{verb}`, and the turn's
  transcript + tool calls are committed to `POST /api/interpretations` — the same committed turn
  record the eval harness grades (`10 §3`). Read-only: state-changing actions are step 4.

Next (`§7 step 4`): inline T2/T3 action approvals — `request_action` → Gate 2 → approve — against
the real write path (`server/actions.go`).

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

In the dev host: the reckon icon in the activity bar → **Investigations**. Sign in, then `+`
seeds an investigation and a row-click opens its document. Activation is logged to the **reckon**
output channel; `reckon: Check Backend Connection` is in the command palette.

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

## Pending seams

- **The TS agent loop is transitional.** `src/agent.ts` is a stopgap: the canonical loop is the
  Go `agent` package, and this extension will drive it as a local sidecar
  (`reckon investigate --stdio`, JSON-RPC over stdio) per the committed decision in
  [`implementation/agent-sidecar.md`](../implementation/agent-sidecar.md). That lands the
  provider seam (multi-LLM), delegate attribution (second PKCE flow against `reckon-agent` on
  the SSO session — see `implementation/jwt-claims.md`), and eval-graded loop behavior; then
  `agent.ts` is deleted. Until then, interpretations post under the analyst's human token and
  are recorded as human-authored.
- **Write actions inline** (`§7 step 4`): `request_action` → Gate 2 → T2/T3 approval, wired to
  `POST /api/actions` + `/api/actions/{id}/approve`.
