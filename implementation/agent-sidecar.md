# The agent loop stays in Go: client plane, sidecar transport, token handoff

Status: **decided** (2026-07-23). This note records the decision, the rejected
alternatives, and the seams it creates. It governs how the workbench (VS Code
extension, `workbench/`) obtains the interactive agent loop.

## 0. The decision in one paragraph

There is exactly one agent-loop implementation: the Go `agent` package —
provider-seamed (`agent.LLM`), delegate-credentialed, and graded by the eval
harness (`design/10`). Every analyst surface is packaging around it
(`design/13 §1`). The VS Code extension reaches it by spawning the `reckon`
binary as a **local sidecar** speaking JSON-RPC over stdio. A TypeScript
reimplementation of the loop and a WASM compilation of the Go loop were both
considered and rejected (§2). The extension remains the sole auth owner and
hands short-lived access tokens to the sidecar over the RPC channel (§5).

## 1. Client plane vs server plane

The architecture is client–server, and the split is load-bearing:

- **Client plane**: the extension (`workbench/`) + the agent-loop sidecar. Runs
  on the analyst's machine. Holds the analyst's tokens and the BYOK model key.
  Talks to the backend only through the public HTTP API.
- **Server plane**: the engine (backend + Postgres/Temporal/Keycloak). Runs
  wherever the deployment puts it — the same laptop in the bundled-local
  topology, or a shared host reached over HTTPS.

**Co-residence is a topology, not a dependency.** In v0 both planes share a
laptop because `reckon start` boots the engine locally; nothing in the client
plane assumes this. The backend location is one URL (`reckon.backendUrl` /
`agent.NewClient(base, …)`) and one OIDC issuer (discovered from
`/api/auth-config`), both already parameterized. Repointing them at a remote
engine is configuration, not design change.

Two commitments make the split hold:

- **The loop runs client-side** (`design/05 §2.7`): the LLM credential lives
  with the surface and never crosses to the backend, wherever the backend is.
- **The client has zero paid awareness** (`design/13`): capability differences
  between deployments appear to the client as API responses, never as client
  forks.

## 2. One loop; rejected alternatives

`agent/` is the canonical loop: capability descriptors → tool definitions, the
model↔tool conversation, transcript commit, the two-token discipline, the
provider seam (`agent.LLM` — Anthropic today, other providers are one
`Complete` implementation each). The eval harness drives this exact code, so
its behavior is pinned by graded baselines.

- **Rejected: a TypeScript loop in the extension.** A second implementation
  diverges from the graded loop, lacks the provider seam, and re-implements the
  delegate-credential logic — eroding `design/13 §1` ("packaging around the
  existing loop, not a second implementation"). The transitional
  `workbench/src/agent.ts` is deleted when the sidecar transport lands.
- **Rejected: compiling `agent/` to WASM inside the extension.** Viable
  (the package is pure stdlib + `uuid`; `net/http` rides fetch on `js/wasm`)
  but its only payoff is a zero-install client, and shipping a local client
  binary is an accepted ask. Costs — a `syscall/js` bridge, poor debuggability,
  Go-runtime instance lifecycle — are paid immediately for a payoff that never
  arrives. Revisit only if a browser-hosted workbench (vscode.dev) becomes a
  requirement.

## 3. Artifact model

- **`reckon` — one binary, two roles.** Client role: `reckon investigate`
  (interactive CLI today; `--stdio` sidecar mode for the extension). Server
  role: `reckon start` (local engine supervisor). The open-core split is
  enforced at `runtime.Run`/`ModuleBuilder` and the repo boundary, not by
  binary count; engine dependencies are downloaded on first `start`, so a
  client-only install that never runs `start` carries no server weight.
- **`.vsix` — never bundles the engine *or* the sidecar binary.** The extension
  discovers `reckon` (setting, then PATH) and degrades with a diagnostic when
  absent — the same honest-surface posture as "backend not running."

## 4. The stdio transport

The extension spawns `reckon investigate --stdio` and speaks JSON-RPC over
stdin/stdout (the LSP-style transport; `vscode-jsonrpc` on the TS side).
Protocol sketch — the RPC surface mirrors the `agent.Session` surface, which is
deliberately small:

- `initialize` — versions exchanged (see below), backend URL, model, config.
- `createSession(investigationID)` / `turn(sessionID, userText)` /
  `cancel(sessionID)`.
- Server→client notifications: turn progress (tool use, tool results, text).
  Streaming deltas land on this same channel when the `agent.LLM` seam grows
  streaming (E.4) — reserved now so streaming is not a protocol break.
- Client→server callback: `getToken(kind)` — see §5.

Two version handshakes, one recipe (the `/status` `api_version` pattern,
`design/13 §2`): extension↔sidecar assert a shared stdio-protocol version at
`initialize`; sidecar↔backend assert API compatibility exactly as the extension
already does. Both fail closed with a diagnostic.

Process lifecycle: the extension owns spawn/respawn; a sidecar crash never
takes down the extension host; sessions are re-creatable from backend state
(the thread is server-persisted; only in-flight turn context is process-local).

## 5. Auth: token handoff, not token exchange

The delegate-attribution contract is `implementation/jwt-claims.md`: the
two-client realm (`reckon` human path, `reckon-agent` delegate path with the
issuer-side `delegate_kind` mapper) makes the claim unforgeable and keeps `sub`
the analyst. Nothing here changes that contract; this section is only about how
the *workbench* obtains tokens from both clients without a password prompt.

- **The extension is the sole auth owner.** It runs the interactive
  authorization-code + PKCE flow against the `reckon` client (built,
  `workbench/src/auth.ts`), then a **second PKCE flow against `reckon-agent`**.
  The second flow completes silently on the realm SSO session cookie set by the
  first — no re-prompt, no password, no preview features, public clients only.
  Refresh tokens for both live in `SecretStorage`; the extension owns refresh.
- **The sidecar holds no refresh tokens.** When it needs a token it calls the
  `getToken(kind)` RPC callback (`kind` ∈ human, delegate) and receives a
  short-lived access token. Loop calls (capability invocation, interpretation
  commit, `request_action`) ride the delegate token; the human token is used
  only where the loop acts as the analyst's plain client (e.g. reading state).
- **Approvals never transit the sidecar.** Approve/reject is extension UI →
  backend directly, on the human token. The backend 403s delegate-token
  approvals regardless (`authz`, `04 §5`) — the client-side rule is defense in
  depth, not the enforcement point.
- **RFC 8693 token exchange is deliberately not used.** Keycloak's standard
  exchange requires a confidential requesting client — impossible on an
  analyst's machine (a secret in a shipped binary is not a secret) — and
  routing the exchange through the backend would let the resource server mint
  the very attribution it is supposed to verify. The SSO-session second flow
  achieves the same end with the machinery we already have.

The CLI's password-grant path (`agent.NewCredential`, ROPC) remains for
dev/eval against the bundled realm; it is not the workbench path and is not
viable against SSO/MFA-fronted realms.

## 6. Remote deployments

What changes when the engine leaves the laptop: the backend URL and the issuer
— nothing else. The realm contract (two clients, roles, mappers — guarded by
`supervisor/keycloak_realm_test.go`) travels with the deployment. A deployment
that fronts a corporate IdP federates it *behind* Keycloak (identity brokering:
the upstream IdP authenticates, Keycloak remains the token issuer), so the SSO
session, the silent second flow, and the delegate stamping all survive
unchanged. TLS on the backend URL is a deployment obligation, not a client
change.

## 7. Sequencing

1. ✅ `AgentTransport` seam in the extension (`workbench/src/agentTransport.ts`
   — sessions keyed by investigation id, turn + cancel + progress events). The
   webview render protocol (`turn.*` messages) is its event half and survived
   as-is (plus `turn.pending`, the honest pre-step-4 approval surface).
2. ✅ `--stdio` mode on `reckon investigate` wrapping `agent.Session`
   (`internal/sidecar`: LSP-framed JSON-RPC server, `getToken(kind, force)`
   callback, both handshakes; `/api/auth-config` now advertises
   `agent_client_id` so the client discovers the delegate client).
3. ✅ `SidecarTransport` in the extension (spawn/respawn, discovery via
   `reckon.sidecarPath` → PATH); second PKCE flow in `auth.ts`
   (`token(kind)`, both refresh tokens in SecretStorage);
   `workbench/src/agent.ts` deleted — one loop again.
4. Streaming (E.4) lands in `agent.LLM` and flows through the reserved
   progress channel (`turn/text` notifications carry round-complete text
   today; deltas slot in without a protocol break).

## Open questions / deferred

- Sidecar discovery UX (setting vs PATH probing order; version-mismatch
  remediation hints) — settle when the transport lands.
- Whether `investigate --stdio` should multiplex sessions across
  investigations in one process (current lean: yes, one sidecar per window).
- Per-vendor `delegate_kind` values (multiple LLM providers) — the realm's v1
  refinement per `implementation/jwt-claims.md`; the engine already reads
  whatever the realm mints.
