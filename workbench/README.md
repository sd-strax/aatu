# reckon workbench

The analyst-facing VS Code extension — the primary product surface. The design is
[`design/13-workbench.md`](../design/13-workbench.md); residence and packaging rationale is in
[`implementation/module-layout.md`](../implementation/module-layout.md) ("The workbench").

## Current state

The sidecar transport sequence (`implementation/agent-sidecar.md §7`, steps 1–4 + E.4
streaming) is complete; of the broader `design/13 §7` slice, steps 5–8 remain (see "Pending
seams"). Built so far:

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
- **The interactive turn loop — via the Go sidecar** (`§7 step 3`, `05 §3.4`,
  [`implementation/agent-sidecar.md`](../implementation/agent-sidecar.md)): there is exactly ONE
  loop implementation — the Go `agent` package, the same code the eval harness grades. The
  extension spawns `reckon investigate --stdio` (discovery: the `reckon.sidecarPath` setting,
  else `reckon` on PATH) and drives it over LSP-framed JSON-RPC (`src/agentTransport.ts`,
  `vscode-jsonrpc`). Auth stays in the extension: the sidecar holds no refresh tokens and asks
  for short-lived access tokens via the `getToken(kind, force)` callback; the BYOK key crosses
  once at `initialize` over the local pipe. Sign-in runs a **second, silent PKCE flow** against
  the `reckon-agent` client (discovered from `/api/auth-config`'s `agent_client_id`, riding the
  Keycloak SSO session), so loop turns carry the delegate token and are recorded as AI-delegated
  — the analyst stays `sub`, `delegate_kind` is issuer-stamped. Read tools dispatch to
  `POST /api/capability/{verb}`; the turn commits to `POST /api/interpretations`. A sidecar
  crash never takes the extension down — the next turn respawns it and re-creates the session
  from backend state. Pending actions render with inline approvals (see "Backend contract"),
  and model text streams token-by-token (see "Streaming").

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

- **Inline approvals** (`§7 step 4`): the document renders the investigation's **durable action
  queue** (fetched on open and re-fetched after every turn and decision — actions from earlier
  turns or sessions are never stranded). Each pending row carries Approve/Reject: the decision
  goes extension → `POST /api/actions/{id}/approve|reject` **directly on the human token, never
  through the sidecar** (approving is the analyst's own act; the backend 403s delegate tokens
  regardless). A T3 approval demands the typed challenge (`04 §5.5`) via input box; rejections
  record a reason. Server explanations (Gate 2 denials, guarded transitions) surface verbatim.

- **Streaming** (`E.4`): model text arrives token-by-token via `turn/text_delta` notifications
  (`agent.StreamingLLM` → SSE → sidecar → the webview's appendable text case). `turn/text`
  (round-complete) fires only when the provider cannot stream — the two are mutually exclusive
  per completion, enforced sidecar-side, so the renderer appends both and never dedupes.

## Document layout

The investigation document is a two-region surface (`design/13 §4`): the **conversation**
(center, measure-capped) and a persistent **state rail** (right) carrying what the analyst
needs at a glance, not buried in the transcript.

Opening an investigation renders **"How this investigation got here"** — the chronological
reasoning thread from `GET /api/investigations/{id}/thread` (`server/thread.go`), reassembled
from `interpretation.recorded` events alone (every lifecycle/action transition pairs one in
the same transaction, so the history is complete with no duplicates, ordered by
`sequence_no`). Each step shows the author (**analyst / AI · model / system** — the
"delegate, never principal" attribution made visible), the interpretation type, rationale,
confidence, and tool-call/evidence counts. The list freezes at the sequence seen on first
load; later acts arrive through the live conversation, so re-fetches never duplicate them.

The rail mirrors the epistemic workflow — what we believe, then what grounds it — with
approvals as an *interrupt*, not a section:

- **Needs your approval** — hidden entirely when nothing waits; pinned above everything when
  something does (an approval window's countdown outranks all standing state). The durable
  action queue with decision-grade cards and the EXPIRED posture.
- **Hypotheses** — the scoreboard leads the standing rail: statements with prediction status
  badges, always present, always evolving.
- **Pinned evidence** — the curation fold; superseded pins struck, never absent.
- **Capabilities** — collapsed to a count (`Capabilities · 4/8 available`). Health detail is
  operator information (`13 §4` homes it in the container view); coverage surfaces where it
  bites — on tool-result rows and in the verdict residual — not as standing chrome.

Conversation rendering: assistant text goes through a **minimal escape-first markdown
renderer** (inline in the webview — the CSP forbids external libraries; every path escapes
before formatting because model text is untrusted). Streamed deltas re-render the current
text segment live, and a tool call closes the segment so later text lands *after* the tool
row, in reading order. Tool rows are one-line disclosures (verb + args preview → ✓/✗ +
coverage) with full args behind `<details>`. Turn metadata (token usage, commit id) renders
muted.

## Pending seams

The `implementation/agent-sidecar.md` §7 transport sequence (steps 1–4, including E.4
streaming) is complete. Of the broader `design/13 §7` slice, steps 5–8 remain: enablement
widgets (`11 §5.1`), raw evidence in reach (read-only OCSF JSON via reckon URIs from cited
refs), the minimal two-layer graph, and the profile trim (`13 §6`).
