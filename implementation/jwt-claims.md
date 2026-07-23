# JWT claim contract

reckon authenticates every request against a Keycloak-issued JWT (Gate 1,
`authz/`). This doc is the authoritative list of claims the engine consumes and,
crucially, the two claims the IdP must be **configured** to mint — the code
assumes correctly-minted tokens and does not (and cannot) provision the realm
that produces them.

The parser is `authz.rawClaims` → `authz.Claims` (`authz/claims.go`); the
verifier is `authz.Verifier` (JWKS discovered via OIDC `.well-known`).

## Claims consumed

| Claim | Source | Consumed for |
|---|---|---|
| `iss`, `exp`, signature | Standard OIDC | Gate 1: signature against the realm JWKS; `exp` re-checked on every request. |
| `sub` | Standard | Becomes `Actor.PrincipalID` on **every event**. The audit trail's human principal. Always a human — see the delegate rule below. |
| `aud` | Standard | Audience confinement, enforced only when `KeycloakClientID` is configured. OSS-solo dev leaves it unchecked. |
| `realm_access.roles`, `resource_access.<client>.roles` | Keycloak-standard | Gate 1 RBAC. Merged + deduped into `Claims.Roles`. Requires the reckon roles (`viewer` / `analyst` / `auditor`) to **exist in the realm**. |
| `preferred_username` | Standard | Log lines only. Never load-bearing for authorization. |
| `tenant_id` | **Custom** | The tenant the principal acts in. Set by the paid governance module in federated tokens; OSS defaults to the singleton tenant when absent. |
| `delegate_kind` | **Custom** | The load-bearing one. Names the LLM delegate that produced the request on the principal's behalf; empty when a human acts directly. Drives every human-vs-AI decision (below). |

## `delegate_kind` — the load-bearing custom claim

`delegate_kind` is the single input that distinguishes "a human did this" from
"an AI delegate did this on a human's behalf." Everything downstream keys off
the actor kind it produces (via the one derivation point,
`server.actorFromClaims`):

- the aggregate's **AI-write-protection allowlist** (`aggregate/command.go`) —
  an `AI_DELEGATED` actor may propose but never approve/reject/conclude;
- Gate 2's **baseline DENY** (AI-no-T3, `action/gate2.go`) — an AI-delegated T3
  can never auto-approve;
- the approve/reject endpoints' **403** for delegate tokens (`server/`);
- hypothesis authorship — AI-authored → `PROPOSED`, human-authored → `OPEN`,
  and acknowledgment is human-only (`aggregate/hypothesis.go`).

Because it is load-bearing, `delegate_kind` MUST be issuer-controlled, never
client-supplied. Two invariants the token-minting flow has to guarantee:

1. **The claim is stamped by the IdP, not chosen by the caller.** A client that
   can set its own `delegate_kind` can impersonate a human (strip it) or forge a
   delegate. The engine derives the actor kind from the claim and NEVER from the
   request body (the seam obligation enforced at every command-issuing handler),
   but that is only sound if the claim itself is trustworthy.
2. **`sub` stays the analyst even in a delegated token.** AI is a delegate, never
   a principal — so a delegated request must carry `delegate_kind=<vendor>` while
   `sub` remains the human analyst. A service-account / client-credentials token
   (whose `sub` is the service account) is architecturally wrong: it would record
   the AI as the principal.

### Minting flow — two-client realm (provisioned)

The bundled realm (`supervisor/keycloak_realm.json`, imported on first start)
ships **two public clients** that together satisfy both invariants without any
preview features:

- **`reckon`** — the human principal path. Carries the audience mapper and
  **no** `delegate_kind` mapper. A token from this client is a human acting
  directly.
- **`reckon-agent`** — the AI-delegate path. Carries an
  `oidc-hardcoded-claim-mapper` that stamps `delegate_kind` (v0: `claude`)
  **issuer-side**, plus the same audience mapper. The surface obtains agent-turn
  tokens through this client: `sub` stays the analyst and the realm roles carry
  (realm roles are on the user, included in any client's token), so AI is a
  delegate on the human's behalf — never a principal.

The two invariants hold structurally:

1. **Issuer-minted, not caller-chosen** — the value comes from the client's
   mapper; a public client cannot inject arbitrary claims, so a caller can
   neither forge `delegate_kind` on the `reckon` client nor override its value on
   `reckon-agent`.
2. **`sub` preserved** — both clients authenticate the same analyst user, so a
   delegated token still records the human as principal.

Neither direction of abuse works: a human token (from `reckon`) can never gain
the claim, and an agent token (from `reckon-agent`) can never shed it. Getting a
non-delegated token requires the analyst's own `reckon`-client credentials —
i.e. the human is present — so `delegate_kind` only ever *reduces* privilege
(the AI-write-protection allowlist + baseline DENY), never escalates.

`supervisor/keycloak_realm_test.go` guards this contract structurally: every
`authz.AllRoles` role is defined, the human client omits the delegate mapper,
and the agent client stamps `delegate_kind` onto the access token. A bad edit to
the realm fails at `go test`, not at an analyst's first login.

**Still a deployment obligation:** the *interactive login* that drives the two
clients — the PKCE/browser flow, and choosing `reckon` vs `reckon-agent` per
turn — belongs to the surface (VS Code extension / CLI auth), not the engine.
`reckon init` provisions the realm on first start; the surface wires the login.
Tests bypass both with a mock OIDC issuer. The v1 refinement, when multiple
delegate vendors matter, is to make the mapper read a user attribute (or add a
per-vendor client) instead of the v0 hardcoded value — the engine side does not
change, it already reads whatever `delegate_kind` the realm mints.

### The artifact ships no credentials and no password grant

Two things that are pure dev/CI scaffolding are deliberately kept OUT of the
distributed realm import (`supervisor/keycloak_realm.json`), because this repo is
public-bound and both are default-credential liabilities:

- **No user account.** The realm ships zero users. A hardcoded-password (and
  formerly `tenant_admin`) account in a public realm is exactly the
  default-credentials footgun a first security review flags.
- **The direct-access (ROPC) grant is OFF** on both clients
  (`directAccessGrantsEnabled: false`). ROPC is the one grant where the password
  transits the *client* instead of staying at the IdP, and nothing in the
  shipping analyst path needs it — the workbench signs in with PKCE. It is also
  structurally impossible against an SSO/MFA-fronted corporate IdP, so it only
  ever worked in the bundled-local topology anyway.

Both are provisioned OUT OF BAND against a running instance by
**`reckon dev-auth`** (`cmd/reckon/dev_auth.go` → `supervisor.ProvisionDevAuth`),
which authenticates with the master bootstrap admin and, via the Admin REST API,
(1) enables ROPC on the `reckon`/`reckon-agent` clients and (2) ensures a login
principal with a chosen password + the engine roles. It is loud that it weakens
the instance's posture and must never run against a shared/hardened deployment.

Consumers by auth path:

- **Workbench (shipping analyst surface)** — PKCE; needs only the *user* to
  exist, so `dev-auth` (or a real admin creating users / a federated IdP) is the
  onboarding step. Does not need ROPC.
- **`reckon investigate` (deferred dev CLI) and `eval` (CI)** — still ROPC via
  `agent.NewCredential`; both require `dev-auth` to have run, and say so on login
  failure.
- **Engine/integration tests** — untouched: they mint their own JWTs against a
  mock issuer (`server.mintToken`), never ROPC against the real realm, so the
  artifact change breaks no test.

The realm-import contract is guarded structurally by
`supervisor/keycloak_realm_test.go`: `TestRealm_ShipsNoCredentialedUser` and
`TestRealm_DirectAccessGrantsDisabled` fail `go test` if either liability creeps
back in. The Admin-REST provisioning flow is covered against an httptest
stand-in (`keycloak_admin_test.go`) so its request shapes are checked without a
running Keycloak.

The **master bootstrap admin remains `admin/admin`** by default
(`ensureBootstrapAdmin`) — a separate, pre-existing weak-dev-default that
hardened deployments rotate; `dev-auth` uses it but does not worsen it.
