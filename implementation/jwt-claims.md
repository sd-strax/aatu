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

### Required minting flow (IdP configuration — not yet built)

The shape that satisfies both invariants is **RFC 8693 token exchange**:

- The interactive surface (VS Code extension / CLI) holds the analyst's session
  token.
- Before driving an agent turn, it exchanges that token at a dedicated
  `reckon-agent` client whose protocol mapper stamps `delegate_kind=<vendor>`.
- The exchange **preserves `sub`** (the analyst) and the analyst's roles, and the
  `reckon-agent` client only ever issues delegated tokens — so a caller can
  neither forge nor strip the claim.

This flow, plus realm provisioning (the three roles, the `tenant_id` /
`delegate_kind` protocol mappers, and the PKCE client for the surfaces), is a
**deployment obligation the code assumes but does not create**. It lands with
the surface auth work and `reckon init` (first-run realm setup). Tests today
bypass it with a mock OIDC issuer that mints tokens directly.

Until it exists, the honest posture is: the *engine-side* enforcement is
complete and unspoofable **given a correctly-minted token**; the minting
discipline is an IdP-configuration obligation, recorded here so it is not
mistaken for done.
