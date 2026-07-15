# Component Architecture — Spec

## Project context

"Cursor for SOC analysts" — AI-native investigation environment with a dynamically-assembled remediation surface. Substrate: VS Code extension (primary), CLI (secondary), Go backend, Next.js web (review panels and approval relay surfaces in SaaS), transport-neutral capability layer for tool federation, and a knowledge service holding institutional context (SOPs, concluded-investigation summaries). Personas v0: threat hunters and IR responders. Workflows v0: investigation (entity-rooted) and hunting (hypothesis-rooted). v0 ships against OCSF fixtures; v1 ships real integrations alongside the fixture corpus; v2 launches the multi-tenant SaaS.

This spec defines the component topology, deployment shapes, authentication, the lift path between deployments, and the operated surface reckon (the company) runs centrally. It assumes the four upstream specs as authoritative input.

## Thread scope

- Component topology of the OSS and paid Go binaries across two deployment shapes
- Solo localhost: process supervision, bundled Postgres + Temporal, agent-loop placement, vendor credential handling
- Multi-tenant SaaS: managed data plane, federated identity, shared investigation, async approval surface
- Authentication and authorization: reckon-operated Keycloak, JWT-borne roles, two-axis evaluation
- The lift path from solo to SaaS, including identity continuity and namespace handling
- The reckon-operated static and service surface (CDN, IdP, approval relay, email, telemetry, MITRE corpus)
- Cross-cutting concerns designed-in at v0 and exercised at v1: rate limiting, credential resolution, health probes, re-normalization scheduling, observability

## Out of scope

- The investigation domain model itself (01-domain-model.md)
- Persistence model (02-persistence.md)
- Capability layer verbs, normalization, identity rules (03-capability-layer.md)
- Action authorization machinery (04-action-authorization.md)
- The knowledge service internals — corpora, embeddings, retrieval mechanics, authoring (06-knowledge-service.md)
- Post-conclusion outputs — export bundle, IOC extraction, candidate SOPs, ticketing handoff (07-post-conclusion-outputs.md)
- The write-side adapter contract — referenced where it matters; full design in 08-write-side-actions.md (symmetric twin of the read-side capability contract)
- Detection authoring as a feature (deferred to v2+; data model accommodates it)
- UI rendering specifics

---

## 1. Decision summary

| Concern | Decision | Reasoning |
|---|---|---|
| Backend language | Go everywhere | Single binary distribution, low cold-start, healthy MCP / cloud-native ecosystem; STIX/OCSF library landscape is workable in any language given the spec's deviations and the codegen-from-schema approach to OCSF |
| Open-core line | Gate operation and governance; never investigative capability or connectors | OSS engine + all adapter classes must be standalone-usable; tenancy and governance are the paid additions; full rationale in §13 |
| Distributions | OSS and paid; two binaries from two repos | Public `reckon` repo defines module interfaces and ships the OSS binary; private `reckon-enterprise` depends on `reckon` and implements the interfaces, shipping the paid binary. The seam is repo-enforced — OSS cannot import paid because paid is not in its import graph |
| Operator | Customer (OSS, paid self-hosted) or reckon (paid reckon-hosted); orthogonal to distribution | Same Terraform/Helm for paid regardless of operator |
| Postgres | Bundled (`embedded-postgres-go`) in OSS; managed typical in paid; bundled still works in paid | Analyst UX in OSS; operational preference in paid |
| Temporal | Bundled (Temporal CLI dev server, SQLite-backed) in OSS; Postgres-backed or managed cluster typical in paid / at scale | Eliminates handrolled task-queue plumbing for action expiry, dispatch retries, reversal sagas, re-normalization, archive bundling, post-conclusion workflow |
| Agent loop | Client-side (extension/CLI) for interactive; server-side Temporal for async | BYOK LLM key never crosses to backend on interactive path; same loop code points at local or remote backend identically |
| LLM provider | BYOK for interactive; tenant-scoped for async | Per-analyst keys via the credential-resolution scheme (§10.2); never reckon-hosted inference at v0–v2 |
| Adapter packaging | Out-of-process JSON-RPC, MCP-compatible; classes are MCP / NATIVE_API / CUSTOM / FIXTURE / SOAR_PLAYBOOK | Polyglot adapter authoring; mature MCP ecosystem reuse; in-process Go plugins explicitly rejected; SOAR delegation is just another adapter class |
| Knowledge service | New service alongside capability layer; `governance_mode: lightweight | gated` config | SOPs and concluded-investigation summaries; LLM-facing context retrieval; mode is a deployment config, both behaviors in OSS |
| Identity provider | Keycloak is the trust root in every shape; customer IdPs federate upstream | OSS: bundled single-realm. Paid self-hosted: customer-operated Keycloak. Paid reckon-hosted: reckon-operated Keycloak. Backend JWT validation logic is uniform. |
| Authorization roles | Live in IdP, carried in JWT | reckon does not cache or mirror roles; tenant admin role changes propagate on next token refresh |
| Token policy | No valid token, no operation | No grace period for client-initiated commands; long-running Temporal workflows carry the initiating principal in workflow context |
| Vendor credentials | Orthogonal to user identity | Resolved via `keychain://`/`vault://`/`env://` (§10.2); never visible to user JWTs or the extension |
| Action layer | Same adapter pattern as reads | Symmetric write-side; remediation, ticketing, comms, TI publication, IT operations all slot in as action types and adapters. SOAR_PLAYBOOK bindings delegate to existing playbooks; native bindings call vendors directly; analyst picks per action. |
| Licensing | Bolt-on; honor-system at v0–v1; signed entitlement file later (air-gap compatible) | Preserve the module seam so a future license check has a single, isolated place to land |

---

## 2. Architectural commitments

These follow from the upstream specs and the decisions above. They are load-bearing across the rest of this spec and the dependent threads.

**1. Two distributions, deployable in any shape.** reckon ships from two repos: a public OSS repo (`reckon`) and a private paid repo (`reckon-enterprise`) that depends on the OSS repo through a stable `module/` interface package. Each repo builds an `reckon` binary; the paid binary is a behavioral superset of the OSS binary (run with `paid.*.enabled: false` it behaves identically). Either binary runs in solo localhost mode or multi-tenant operation mode — deployment-mode is a configuration dimension, not a code-path dimension. The aggregate, capability resolver, normalizer, identity resolver, policy engine, knowledge service, and Temporal worker are identical across shapes. What differs across deployment shapes is what's wired up: Keycloak realm vs. native user, vault paths vs. OS keychain, S3 side store vs. local table, multi-analyst WebSocket fan-out vs. single-analyst direct WebSocket, etc.

**2. Local-first by construction.** Solo localhost runs with zero reckon data-plane involvement. Customer investigation data — events, STIX nodes, OcsfEvents, transcripts, SOPs — never leaves the laptop unless the analyst lifts to SaaS. The reckon-operated surface that solo mode depends on is limited to: reckon's Keycloak (for auth), reckon's CDN (for binary, policy, fixture, MITRE, adapter-registry distribution), and optional approval-relay + transactional email (only when the solo subscriber configures `approver_emails`). Telemetry and licensing intakes, if any, are opt-in.

**3. Identity is reckon's, always.** Both deployment shapes authenticate against reckon's Keycloak. There is no anonymous or local-OS-only identity model. Solo subscribers are native reckon IdP users; SaaS org members federate from their corporate IdP upstream into reckon's Keycloak. Every event written records a principal whose identity was verified against reckon's IdP at command time.

**4. Authorization is two-axis.** Per-request authorization runs in two gates: an RBAC gate evaluated against JWT claims (does this principal hold the role required to attempt this kind of operation?), and an action-authorization gate per 04-action-authorization.md (given that the principal can attempt it, does policy auto-approve, require two-party, or deny?). Solo subscribers collapse Gate 1 trivially because they hold every role in their personal tenant; Gate 2 still applies and the AI delegate constraints remain in force.

**5. The capability layer is symmetric across reads and writes.** Read-side verbs and write-side action types share the same binding/adapter/parameter-mapping structure. An adapter is one or more JSON-RPC operations served by an out-of-process binary that reckon spawns. Adding a remediation tool — EDR, MDM, IdP, ticketing, comms, TI platform, or anything else — is "register an adapter, add bindings, declare an action descriptor." No structural change. The write-side contract is specified in 08-write-side-actions.md; the architecture is symmetric and known.

**6. Knowledge service is a sibling, not a member, of the capability layer.** Capability layer outputs are world-facing observations: OcsfEvents and STIX nodes with telemetry provenance. Knowledge service outputs are internal context: SOPs the LLM consults during reasoning, similar past investigations the LLM cites in rationale. Keeping them separate preserves the capability layer's pure-I/O property and gives the knowledge service its own retention, privacy, and audit story.

**7. The agent loop runs client-side. BYOK keys never cross to the backend.** The VS Code extension (or the future CLI agent surface) holds the analyst's LLM key in the OS keychain. It builds tool definitions from the backend's `/capabilities` endpoint plus the knowledge service's `/knowledge/tools` endpoint, calls the LLM directly, dispatches tool calls to the backend over authenticated HTTP, and posts the resulting Interpretation command together with the transcript bytes for hashing and side-store linkage. The backend never sees the LLM key in either deployment shape.

**8. Tenant-scoped by construction; multi-tenant only in SaaS.** Per the per-tenant namespace UUID rule from 01-domain-model.md Architectural Commitments #3 and #5, every tenant — solo or SaaS — has its own immutable namespace UUID assigned at creation. Cross-tenant identity collision is structurally impossible. Solo mode is a tenant of one; SaaS mode is many tenants on shared infrastructure with row-level security as defense-in-depth on top of the namespace property.

---

## 3. Runtime topology

The reckon binary runs in two dependency configurations distinguished only by what Postgres / Temporal / Keycloak it points at. Solo laptop and self-hosted multi-user are both the same OSS binary; the paid binary (built from `reckon-enterprise`, which depends on the OSS engine) adds module-driven behavior on top of the same code paths. Per §13, the open-core line and the operator orthogonality govern *what* is loaded and *who* runs it; this section describes the *runtime* once.

### 3.1 Process model

**Bundled-deps configuration** (OSS default; also valid for paid self-hosted at small scale):

```
reckon start
  ├── postgres            (embedded; persistence for aggregate,
  │                        knowledge service, side stores, projections)
  ├── temporal            (dev server; SQLite-backed at v0, carrying its
  │                        own persistence separate from Postgres)
  ├── keycloak            (single realm bundled with the OSS install;
  │                        multi-realm config activated by the tenancy
  │                        module — see §4)
  └── reckon-backend        (Go: aggregate command handler, capability
                           resolver, knowledge service, Temporal worker,
                           HTTP+WS server)
```

`reckon start` runs the supervisor in the foreground or as a launchd / systemd / Windows service. `reckon stop` performs an orderly shutdown. `reckon status` reports component health. The supervisor cascades restarts (Temporal exit → restart; Postgres exit → fatal — mid-session restart corrupts in-flight transactions, fail fast).

**Managed-deps configuration** (typical for paid distributions, either operator):

Stateless reckon-backend workers behind a load balancer point at managed Postgres, managed Temporal, and a Keycloak deployment (either bundled-by-reckon or customer-operated HA — Keycloak remains the trust root regardless). State lives where it would in bundled mode; the difference is who operates the storage layer. Managed vs bundled is a connection-string concern, not a code-path one.

### 3.2 Postgres

Bundled via `fergusstrange/embedded-postgres` or equivalent; the supervisor downloads the binary on first run if not present, data lives under `~/.reckon/pg/`. Same schemas regardless of dependency configuration:

- `reckon_main` — investigation events, STIX object store, projections, side stores (`ai_tool_calls`, `ai_transcripts`)
- `reckon_knowledge` — SOP repository, concluded-investigation summary index, pgvector embeddings (see 06)

The bundled Temporal dev server carries its own SQLite-backed persistence at v0 and does not use this Postgres instance; a Postgres-backed or managed Temporal is the v1+/scale option (§3.3).

`pgvector` is required for the knowledge service. The bundled Postgres ships with the extension preinstalled. Managed-deps deployments require pgvector on the chosen Postgres provider. If a future deployment context demands an alternative (Postgres distributions without pgvector availability), the knowledge service's storage interface is abstracted enough to swap.

When the tenancy module is on (§4), `reckon_main` activates row-level-security policies keyed on `tenant_id`; the schema gains no new tables. Per-tenant namespace UUIDs (01-domain-model.md Architectural Commitments #3) remain the structural guarantee against cross-tenant id collision; RLS is defense-in-depth.

### 3.3 Temporal

Bundled as the Temporal CLI dev server (single-binary, SQLite-backed at v0) in OSS; a Postgres-backed Temporal or managed Temporal cluster is the v1+/scale option and typical in larger deployments. The reckon-backend process registers a Temporal worker on the `reckon` task queue (per-tenant task queues when the tenancy module is on).

**Workflow inventory.**

v0 — durable mechanics with no agent reasoning:
- `ActionLifecycle(action_id)` — sleeps until expiry or signal-on-approval; on approval, dispatches; handles the retry budget per 04 §6.1; emits the chain of `Action*` events
- `ReversalSaga(reversing_action_id)` — runs the reversal action; on success, posts `ActionReversed` against the original
- `RenormalizePass(class_uid, version_from, version_to)` — long-running batch, cancellable, checkpointed
- `ArchiveInvestigation(grouping_id)` — bundle, sign, write to archive target
- `PostConclusionPipeline(grouping_id)` — IOC extraction, candidate-SOP generation, optional ticketing handoff (see 07)
- `SummarizeForKnowledgeIndex(grouping_id)` — extracts the structured summary and embeddings written into the knowledge service (see 06)

v1 addition — top-level investigation orchestrator:
- `InvestigationLifecycleWorkflow(grouping_id)` — spawned at `InvestigationCreated`, lives until `InvestigationArchived`. Owns investigation-level orchestration state (active hypotheses summary, pending actions, scheduled hunts, lifecycle timers like "warn analyst if no activity for 7 days," "auto-archive if concluded for 90 days"). Receives signals on major events. Spawns and supervises v0 child workflows — `ActionLifecycle`, `ReversalSaga`, `PostConclusionPipeline` reparent as children rather than independent roots. Survives extension restarts, host reboots, and (with tenancy module) multi-analyst handoff. **Does not drive interactive analyst turns**; tracks them as observed signals while the extension owns the interactive loop.

v2 additions — server-side agent loops for async work:
- `BackgroundHuntWorkflow(investigation_ref, hunt_spec)` — analyst kicks off "find all signs of lateral movement in the past 72 hours" and goes home. The workflow drives its own agent loop server-side using tenant-scoped LLM credentials (resolved via the credential indirection scheme §10.2 — separate from per-analyst BYOK keys). Records Interpretations against the parent investigation; notifies the analyst on completion.
- `ScheduledInvestigationWorkflow(spec)` — cron-shaped periodic re-runs; same agent-loop substrate.

Tenant lifecycle workflows (tenancy-module only, see §4.3): `ProvisionTenant`, `SuspendTenant`, `DecommissionTenant`, `LiftSolo`.

The Temporal worker pool runs in the same OS process as the reckon-backend; there is no separate worker binary. The OSS install stays at three managed processes (Postgres, Temporal server, reckon-backend) plus bundled Keycloak. v1/v2 additions do not change the process count.

### 3.4 Agent loop and capability adapters

**Interactive vs async execution boundary.** The agent's reasoning runs in two places by design:

- **Interactive synchronous turns** (analyst types, AI responds, tools dispatch in real time) run **client-side in the VS Code extension**. The extension holds the analyst's BYOK LLM key in the OS keychain; the LLM call goes from the extension directly to the provider; the backend never sees the LLM key in this path.
- **Async / long-running agent work** (background hunts at v2+, scheduled re-runs at v2+, post-conclusion summary generation, candidate-SOP drafting) runs **server-side as a Temporal workflow**, using **tenant-scoped LLM credentials** resolved per §10.2 — a separate credential from per-analyst BYOK keys.

Why two paths:
- Interactive turns need sub-second token streaming. Temporal activity overhead is fine for minutes-to-hours work, less fine for back-and-forth turns.
- Async work needs durability — the IDE may not be open, the host may be down, the analyst may have handed off. State has to live outside the extension process. Temporal is exactly that.
- Credential separation is deliberate: BYOK keys stay analyst-private and are never used by server-side workflows. Server workflows use tenant-configured credentials, which the tenant admin can scope, audit, and rotate independently.

Both paths share the same capability layer, knowledge service, authorization gates, and aggregate. They write Interpretations to the same reasoning thread. Audit is uniform: principal recorded on every Interpretation, delegate recorded as the AI agent (whether running client-side or server-side), provenance recorded on every output.

**Interactive turn mechanics.** The VS Code extension (or CLI when it grows an agent surface, post-v0) holds the BYOK LLM key in the OS keychain. On session start it:
1. Authenticates against Keycloak via PKCE OAuth flow, caches the token
2. Calls `/capabilities` on the backend to fetch the capability descriptor list, trimmed to verbs whose tenant config resolves to a healthy binding
3. Calls `/knowledge/tools` to fetch the knowledge-service tool descriptors (SOP recall, similar-investigation recall)
4. Constructs LLM tool definitions from the union; system prompt includes reckon's reasoning conventions and the implicit-retrieval results for the current investigation context

When the LLM emits a tool call, the extension dispatches it to the backend at `/capability/<verb>` or `/knowledge/<op>` (HTTP POST, JWT in `Authorization` header), feeds the result back to the LLM, repeats. When the loop terminates, the extension posts the final Interpretation command together with the transcript bytes to `/interpretations`; the backend hashes the bytes, writes the side-store row, and appends the event in one Postgres transaction.

Capability adapters run as out-of-process binaries spawned by the backend. The backend speaks JSON-RPC over stdio to each adapter; the contract is MCP-compatible by default but does not require an MCP server. First-party adapters (including SOAR_PLAYBOOK adapters — see 03) ship as separate Go binaries in the same release; third-party can be any language.

### 3.5 Vendor credentials

Resolved through the uniform indirection scheme (§10.2): `keychain://`, `vault://`, `env://`, or `inline://`. The adapter receives a `credentials_ref` in its operation parameters and resolves the secret on demand; plaintext is never persisted outside the per-call invocation. Laptop installs default to `keychain://`; server installs default to `vault://` or `env://`. The resolution is uniform across distributions and operators — the only difference is which URI scheme the tenant config points at.

### 3.6 Network dependencies

reckon is local-first, not offline-only. Required network reachability:
- **Keycloak (trust root)** — for initial auth and periodic token refresh. Issuer URL is per-deployment config. Bounded offline tolerance: access-token validity (default 1h) for absolute disconnect; refresh-token validity (default 30d) for reconnect-after-disconnect.
- **Signed-bundle distribution surface (§11)** — software updates, signed policy bundles, fixture corpus, MITRE corpus, adapter registry. Pull-on-startup with a fallback to last-cached. Mirrorable for air-gapped customers.
- **Approval relay + transactional email** — only when `approver_emails` is configured and a TWO_PARTY policy fires, or (with tenancy module) multi-analyst async approval is in use.
- **Vendor APIs** (v1+) — direct from the executing host to vendor for read-side capability calls; credentials per §3.5.
- **LLM provider** (BYOK for interactive; tenant-scoped for async) — direct call from the executing host; not proxied through reckon.

The reckon-backend process does not require outbound network for normal investigation work once the token is fresh and cached static surfaces are loaded. An analyst running a hunt against fixtures on a plane works fine until the access token expires.

### 3.7 Tenant model

The tenant primitive is always present in the data model: every tenant-scoped row carries a `tenant_id UUID NOT NULL`, defaulting to the single OSS tenant (`00000000-0000-0000-0000-000000000001`, "tenant 1"). That single tenant's namespace UUID is generated when its row is seeded into `reckon_main.tenants` and is immutable thereafter — `tenant_id` is the partition key; `namespace_uuid` is the per-tenant identity namespace (01-domain-model.md Architectural Commitments #3) and is a distinct value. The principal recorded on every event is the Keycloak-issued user id, carried in the JWT.

When the paid tenancy module is on, the schema is unchanged; what activates is RLS enforcement, multi-realm or claim-routed Keycloak configuration, per-tenant vault paths, and the tenant lifecycle workflows. See §4.

---

## 4. Multi-tenant operation (tenancy module)

When the paid tenancy module is loaded (§13.2), the following capabilities activate on top of §3's runtime. With the module off, this section's behaviors are inert and the runtime collapses to the single OSS tenant.

### 4.1 Tenant-aware data plane

- **Postgres RLS policies** activate on `reckon_main` keyed on `tenant_id`. Defense-in-depth on top of per-tenant namespace UUIDs (cross-tenant id collision is structurally impossible regardless of RLS).
- **Temporal namespaces** become per-tenant; workflow ids include `tenant_id` prefix for visibility filtering.
- **Side stores** (`ai_transcripts`, `ai_tool_calls`) gain per-tenant scoping — local Pg side tables in bundled-deps mode, S3 per-tenant prefixes in managed-deps mode.
- **Vault** holds vendor credentials per tenant, accessed by adapter workers; never visible to user JWTs or the extension.

### 4.2 Capability adapter deployment with multi-tenancy

The §6 read/write deployment shape gains a per-tenant config dimension:

- **Read-side: analyst host.** Default. Per-analyst vendor credentials resolved locally; the backend never sees the credentials. Same shape as the OSS single-tenant case.
- **Read-side: backend-side workers.** For tenants that require vendor credentials off analyst hosts (governance, IP allowlisting on vendor APIs, rate-limit pooling across analysts). Adapter binaries run as backend-side workers; analyst's extension calls the backend, which dispatches to the worker fleet. Vendor credentials live in vault, accessed only by the worker.
- **Write-side: always backend-side at v0–v2.** Action dispatch runs as a Temporal workflow on the backend worker fleet. Vendor write credentials live in vault, accessed only during the workflow's execute step. The `adapter_request_id` correlated in `ActionDispatched` events (02-persistence.md §3) is the Temporal workflow id. The write-side adapter contract is specified in 08-write-side-actions.md.

"Backend-side" means the same backend that runs the aggregate. In reckon-hosted paid this is reckon's cloud; in self-hosted paid this is the customer's cloud. Either way the binary is the same.

### 4.3 Tenant lifecycle workflows

Run in the operations namespace (separate from any customer tenant namespace):

- `ProvisionTenant(...)` — assign namespace UUID, create realm or claim mapping, allocate vault path, seed default policies, configure default adapters, create tenant_admin user
- `SuspendTenant(tenant_id)` — read-only mode; no aggregate writes accepted
- `DecommissionTenant(tenant_id)` — export → delete; final export bundle delivered to a customer-specified target
- `LiftSolo(source_user_id, target_tenant_id, mode)` — handles the lift path (§9)

### 4.4 Async approval surface

TWO_PARTY actions and any AI-proposed T2/T3 the requesting analyst hasn't picked up route through the approval relay (§11):
- Approver receives an email (via the transactional email path) with a signed deep link
- Click lands on the web approval app, which authenticates against Keycloak and renders the same review panel the IDE shows
- Approval signal is queued in the relay; backend polls or receives a push and processes the approval
- Approvers may or may not be subscribers in that tenant — if they're not, the email-based flow uses one-time email-verified deep-link auth scoped to the specific action only

This same mechanism powers OSS-mode `approver_emails` (when the single-tenant install configures peer review — relay can run alongside an OSS install if the customer chooses; the operational tooling around it is a governance-module concern) and tenancy-module-enabled multi-analyst `secondary_approver_pool` (drawn from Keycloak users in the tenant's realm).

---

## 5. Authentication and authorization

### 5.1 Keycloak as the trust root

Keycloak is the identity provider in every deployment shape — OSS, paid self-hosted, paid reckon-hosted. Every backend command-handler RPC validates a JWT issued by Keycloak. The issuer URL is per-deployment config; JWT validation logic and claim extraction are uniform across shapes.

**Who operates Keycloak.**
- **OSS** — Keycloak is bundled in single-realm mode. The OSS install owns it; the customer can use the Keycloak admin console directly to manage users.
- **Paid self-hosted** — customer-operated Keycloak (HA recommended; can be the bundled reckon image or the customer's existing Keycloak deployment).
- **Paid reckon-hosted** — reckon-operated Keycloak (HA, multi-realm).

**Realms and federation.**
- **OSS / single-tenant** — native Keycloak users in a single realm. Standard email/password + MFA, OIDC PKCE flow from the extension.
- **Tenancy module on** — each tenant has either its own realm (stronger isolation) or its own group + tenant claim within a shared realm. The realm-vs-claim choice is operational and does not affect backend authorization logic.
- **BYO IdP** — customer IdPs (Okta, Entra, Google Workspace, Auth0, generic SAML/OIDC) federate upstream into Keycloak. Users sign in through their corporate IdP; Keycloak mints the resulting JWT. The governance module ships federation setup helpers and role-mapping templates (§13.2); the raw Keycloak admin console supports BYO IdP without those helpers, just less ergonomically.

**Tenant management.**
- OSS single-tenant: `tenant_id` claim defaults to 1; no inter-tenant boundary to manage.
- Tenancy module on: tenant admins manage their own users in their realm/group via the governance module's tenant-admin UI (which proxies the Keycloak admin API) or via raw Keycloak admin console. They do not have access to other tenants. In reckon-hosted paid, reckon operations staff have admin access to tenant lifecycle (provision/suspend/decommission) but not to tenant data.

### 5.2 JWT structure

Standard OIDC with these reckon-specific claims:

```
sub               reckon-issued user id (stable across federation)
email             user's verified email
tenant_id         active tenant for this session (solo: personal tenant;
                  SaaS: org tenant the user is acting in)
tenant_memberships array of {tenant_id, roles[]} — all tenants the user
                  belongs to, used by the IDE to allow tenant switching
roles             array of role names valid for the active tenant_id
                  (drawn from the canonical role set in §5.4)
delegate_kind     "HUMAN" (the reckon-IdP-issued user is always a human;
                  AI agents are delegates, not principals)
exp, iat, nbf     standard
```

Roles live in Keycloak as group memberships within the tenant's realm. `roles` claim is computed at token issuance from the user's current group memberships. **reckon does not cache or mirror roles in its application database.** A tenant admin removing a user from a role takes effect on the next token refresh.

### 5.3 Token policy

**No valid token, no operation.** Every client-initiated RPC validates the JWT against Keycloak's signing keys at the moment of the command. Expired, unverifiable, or revoked tokens cause 401. There is no last-known-good fallback.

- **Synchronous IDE/CLI → backend RPCs** validate in middleware on every request.
- **WebSocket connections** validate at handshake and re-validate on each command frame; expired tokens cause connection drop and re-auth prompt.
- **Refresh** is the extension's responsibility; it watches `exp` and refreshes proactively. Refresh failure surfaces as a re-auth UI; until completed, no new commands succeed.
- **Offline tolerance** is bounded by access-token validity (1h default) for absolute disconnect, and by refresh-token validity (30d default) for reconnect-after-disconnect.

**Workflow-context exception.** Long-running Temporal workflows (action dispatch, reversal sagas, re-normalization, archive bundling, post-conclusion pipeline) carry the *initiating principal* in workflow context. The token rule applies at the command boundary that started the workflow (start command was JWT-validated). Subsequent system-emitted events (`ActionDispatched`, `ActionResulted`, etc.) record the initiating principal regardless of whether their token is currently valid. This matches the 01 actor model: principal is who's responsible, not who's pushing the bytes. If a user is offboarded mid-workflow, the workflow completes (already authorized) but no new commands from that user succeed.

### 5.4 Canonical role set

The roles below are the v0+ set used as Keycloak group memberships and rendered into JWT `roles` claims. Tenants pick which roles to issue to which users. A user can hold multiple roles; the union of capabilities applies.

| Role | Capabilities |
|---|---|
| `viewer` | T0 read across permitted investigations; no writes |
| `analyst` | All of `viewer` + T1 mutations (create/edit hypotheses, Sightings, Notes, lifecycle transitions); request T2/T3 actions (subject to 04 policy) |
| `approver` | All of `analyst` + approve T2 actions via single confirm |
| `senior_approver` | All of `approver` + approve T3 actions via typed challenge; eligible for two-party secondary pool |
| `policy_author` | Edit CEL policies in draft; cannot ship them alone |
| `policy_signer` | Sign off authored policies (`signed_off_by`); production deployment requires this role |
| `sop_author` | Edit SOPs in draft; cannot publish them alone |
| `sop_signer` | Sign off authored SOPs; publication requires this role |
| `tenant_admin` | Manage users and role assignments within the tenant; configure tenant settings (adapter bindings, `approver_emails`, etc.) |
| `auditor` | Read-only access to investigations, action history, full audit chain; no writes |
| `ti_admin` | Administer threat-intel publication: review IOC candidates and authorize `ioc.publish_*` actions, manage TI platform integrations (introduced by 07 §3.3) |

**OSS single-tenant installs collapse roles to the install owner by default.** The first user holds every role; their JWT carries the union; RBAC Gate 1 always passes. The action-authorization Gate 2 (04's machinery) still applies, including the AI-delegate constraints that produce friction proportional to risk regardless of how many roles the principal holds. An OSS multi-user install (a small team running OSS on shared infra) assigns roles via the bundled Keycloak admin console — functional but raw; the governance module ships the polished tenant-admin UI around the same operations.

`policy_author` / `policy_signer` and `sop_author` / `sop_signer` are operationally meaningful only when `governance_mode: gated` (see 06 §2.2 for the SOP authoring lifecycle and 04 §4.1 for policy authoring and sign-off). In `lightweight` mode the split collapses — anyone with the parent role can edit and ship.

### 5.5 Two-axis evaluation

Every state-changing operation passes through two gates:

**Gate 1 — RBAC (role-based, JWT-borne).** Does the principal hold the role required to attempt this kind of operation? Cheap, evaluated first, sourced from JWT claims. Failure: 403 with the missing role surfaced.

**Gate 2 — Action authorization (04's machinery).** Given that the principal can attempt it, does policy auto-approve, require manual confirmation, require two-party, or deny? Includes blast-radius escalator, AI-delegate constraints, evidence-derivation checks, and any tenant-authored CEL policies. CEL evaluation context (04 §4.2) is built from the aggregate state at evaluation time.

Both gates must pass. The reasoning thread records both outcomes; the policy evaluation is captured in the `PolicyEvaluated` event (02 §3) regardless of result.

### 5.6 Tool credentials are orthogonal to user identity

User identity (reckon IdP, JWT) and tool credentials (vendor API keys, OAuth tokens for Splunk / CrowdStrike / Okta / etc.) are entirely separate auth layers. They never appear in the same envelope.

- **User auth** (JWT) gates *every* backend RPC and every aggregate write. Tells the backend who is making the request.
- **Tool auth** (per-adapter credential references) gates outbound calls to vendor systems. Tells the vendor system that reckon (acting on behalf of an analyst) is authorized to read or write.

Solo: user auth via reckon Keycloak; tool credentials in OS keychain.
SaaS: user auth via reckon Keycloak (federated); tool credentials in vault, scoped per tenant.

The JWT never carries vendor credentials. The vendor credentials never appear in event provenance. An adapter receives a `credentials_ref` in its operation parameters and resolves to bytes only at the moment of the outbound call.

---

## 6. Capability layer deployment

### 6.1 Read-side

Default deployment site is the analyst's laptop in both modes. The agent loop in the extension calls the local backend at `/capability/<verb>`; the backend resolves to a binding, spawns or reuses the corresponding adapter process, sends the JSON-RPC request, normalizes the response per 03-capability-layer.md §4, writes the resulting OcsfEvent and ObservedData, and returns the `CapabilityResult` envelope.

**SaaS-tier opt-in: cloud-side read adapters.** Tenants whose governance requires vendor credentials off analyst laptops switch the read-side deployment to a cloud worker fleet. Same adapter binaries, same JSON-RPC contract, same normalizer pipeline. The backend's resolver picks the binding, dispatches to the worker fleet, awaits the response. The shape of the customer-facing API is unchanged; the mode is invisible above the resolver.

### 6.2 Write-side

Always cloud-side in SaaS at v0–v2. Solo localhost runs writes in-process with fixture-only bindings at v0; v1 enables real write adapters on the laptop for the personal tenant.

Write actions execute as Temporal workflows (`ActionLifecycle`), which:
1. Wait for approval (signal-on-approve) or expiry (timer)
2. On APPROVED, resolve the binding and call the write-side adapter operation
3. Apply the retry budget per 04 §6.1 with attempts logged to the `Execution` sub-record
4. Emit `ActionDispatched` and `ActionResulted` events with workflow context as the principal carrier
5. On reversal request, instantiate a `ReversalSaga` workflow

The write-side adapter contract (operation declaration, idempotency key, `adapter_request_id` correlation) is specified in 08-write-side-actions.md. This spec owns only the dispatch topology — the `ActionLifecycle` workflow that invokes it.

### 6.3 Adapter discovery

Adapters are discovered through signed manifests distributed via reckon's CDN (the adapter registry; §11). Each manifest declares: adapter name, version, `AdapterClass` (MCP / NATIVE_API / CUSTOM / SOAR_PLAYBOOK / FIXTURE; 03 §5.4), supported operations, parameter schemas, supported action types (for write-side adapters), and a verification signature.

Tenants pin specific adapter versions in their config. Pinning is per-tenant; there is no global version. Adapter binaries are downloaded on demand and cached locally; manifests verify against the reckon CDN's signing key before any binary is invoked.

### 6.4 Verb and action-type registration

The verb catalog (03 §2) and the action-type manifest (04 §2) are extensible without spec changes. New verbs and action types are registered by:
1. Implementing an adapter that supports the corresponding operation
2. Declaring a `CapabilityDescriptor` (verb) or `ActionDescriptor` (action type) in the adapter's manifest
3. Adding bindings in tenant config

The descriptor declares: name, input/output schemas, intent description (consumed by the LLM), default tier (action types only), reversibility mapping (action types only), and optional D3FEND technique (action types only; see §14 companion edits).

`list_capabilities` (03 §2.8) and the analogous `list_action_types` walk the registered descriptors and trim by tenant configuration and adapter health, so the LLM only sees what's currently usable.

---

## 7. Knowledge service deployment

The knowledge service runs as a sibling to the capability layer, hosted in the same backend process. It exposes two corpora — SOPs and concluded-investigation summaries — through a unified retrieval API consumed by the agent loop.

Storage:
- **Solo**: `reckon_knowledge` schema on the bundled Postgres with pgvector; SOP content, summary content, embeddings all local.
- **SaaS**: managed Postgres + pgvector, per-tenant isolation; same data shape; identical retrieval API.

The service spec — corpus schemas, summary extraction, retrieval mechanics, audit linkage, authoring UX — lives in 06-knowledge-service.md. From the component-architecture perspective the service is a known-shape component: per-tenant, pgvector-backed, exposed via `/knowledge/*` endpoints, callable by the agent loop's tool surface, audit-linked to Interpretation events through the `consulted_sops` and `consulted_similar_investigations` provenance fields.

---

## 8. Shared investigation (SaaS only)

Solo localhost has exactly one analyst per tenant; shared-investigation mechanics do not apply. SaaS multi-tenant deployments may have multiple analysts subscribed to the same investigation simultaneously, and this section covers the runtime behavior that emerges.

### 8.1 Real-time fan-out

The aggregate's transactional event-append + projection-update model (02 §4) is unchanged. After commit, a Postgres `NOTIFY` fires on a channel keyed by `(tenant_id, investigation_id, event_type)`. A long-lived `LISTEN`er in the backend fans the event out to all WebSocket connections subscribed to that investigation in that tenant.

IDEs apply event deltas to their projection cache and re-render. Optimistic UI for the local analyst's own writes (write goes out, UI updates immediately, server confirms), pull-and-merge for incoming peer writes. On disconnect / reconnect, the IDE rehydrates the full projection from the current state plus a since-cursor to catch up missed events.

### 8.2 Concurrency

- **Append-only paths** are collision-free by construction. Two analysts independently recording Interpretations or adding Sightings produce two separate events; both succeed.
- **Status changes on shared nodes** use the aggregate's optimistic concurrency. Two analysts simultaneously moving the same `x-hypothesis` to SUPPORTED produce the second writer's command rejecting on `(aggregate_id, sequence_no)` collision; their IDE refreshes and offers the choice to retry, edit, or skip.
- **Action review** is handled by `assignee_ref` (04 §5.4) — first analyst to claim wins; others see the panel update in real time.
- **Free-text fields** (rationale, description, name) are last-writer-wins on the aggregate level; the IDE may surface a "Bob just changed this" toast when receiving a peer's update.

OT/CRDT-style real-time co-editing is explicitly out of scope. Analysts rarely co-author the same string at the same instant in the SOC workflow; the cost of that machinery is not justified by the actual use case.

### 8.3 Two-party approval

PENDING_SECONDARY (04 §3.2) is fully active in SaaS shared investigations. Primary analyst approves with the typed challenge; action moves to PENDING_SECONDARY; secondary approver pool (drawn from the policy's `secondary_approver_pool` or the `senior_approver` role bearers in the tenant) receives a notification; secondary analyst approves with their own typed challenge; action moves to APPROVED. Either side can reject; expiry timers run as Temporal timers within the `ActionLifecycle` workflow.

### 8.4 Async approval

Slack/email/mobile deep links route through the approval relay (§11). The approver clicks, lands on reckon's web approval surface authenticated against their Keycloak identity (or one-time email-verified link if they're not a subscriber), reviews the same panel the IDE shows, and approves or rejects. The relay queues the decision and the backend processes it on the next poll.

### 8.5 Presence

Per-investigation presence (which users are currently viewing, who's editing what) is ephemeral. Stored in an in-memory map keyed on `(tenant_id, investigation_id)` with TTL on disconnect. WebSocket presence frames flow to all subscribers. Not persisted to the aggregate.

---

## 9. The lift path

The lift moves an OSS instance's investigation work into a paid multi-tenant aggregate. It is not a rewrite — it is a replay of the same events into a different deployment of the same backend. Identity continuity (per-tenant namespace UUID) is the property that makes it clean. This is the multi-instance consolidation mechanism: an operator running N OSS instances (one per environment) consolidates them onto a single paid multi-tenant deployment when the operational overhead of N instances justifies adopting the tenancy module.

### 9.1 Sub-path A — OSS lifts to a fresh tenant of one (primary)

The default lift. The OSS install already has a Keycloak identity; its single tenant has namespace UUID `N_local`. The "lift" is a re-pointing of where that tenant's data lives.

Steps:
1. Provision a paid tenant with namespace UUID = `N_local`. The same UUID is preserved; every STIX id remains stable.
2. Replay the local `investigation_events` stream into the paid aggregate (`INSERT ... ON CONFLICT DO NOTHING` on `(aggregate_id, sequence_no)`).
3. Copy `stix_*` rows and `stix_edges` rows for this tenant.
4. Upload Layer B side stores by content hash: `ai_tool_calls` and `ai_transcripts` rows transfer to the paid deployment's object store, references on Interpretation events resolve through the new store.
5. Copy SOP repository rows and concluded-investigation summary index.
6. Repoint the IDE config at the paid backend endpoint. The user's existing JWT is still valid; on next refresh, the `tenant_id` claim points at the paid tenant (which has the same UUID as the OSS tenant did).

The user's data is identical, just hosted differently. The principal recorded on every event is unchanged. No aliasing edges, no re-id, no migration drama.

When consolidating N OSS instances, Sub-path A runs N times — each install lifts into its own tenant within the paid multi-tenant deployment. Analysts gain a cross-tenant console (governance module) and switch tenants via the JWT's `tenant_memberships` claim.

### 9.2 Sub-path B — joining an existing tenant

Harder, because the OSS install's namespace `N_local` differs from the target tenant's `N_tenant`. v0 default behavior:

**The local data parks as a personal-scratch read-only side.** The user retains read access to their OSS tenant alongside their new shared tenant; their JWT carries `tenant_memberships` for both. They write only into the new shared tenant going forward. Their OSS investigations do not pollute the shared tenant's namespace.

Two heavier alternatives, available on request post-v0:
- **Re-id** — walk every STIX node in the migrated investigations, recompute UUIDv5 under `N_tenant`, rewrite events accordingly. Heavy but produces a clean unified namespace.
- **Alias-bridge** — migrate with original `N_local` ids and write `aliases` edges (01 EDGE TYPES) between `N_local` and `N_tenant` entities where they refer to the same real-world thing. Cheaper than re-id, but the alias graph is queried on every cross-tenant pivot.

Sub-path B's UX matters more than its implementation; getting it wrong means users won't lift, they'll restart. v0 doesn't ship Sub-path B at all. v2 ships the personal-scratch default.

### 9.3 What stays on the OSS install after a lift

By default, all data migrates to the paid deployment and the OSS install becomes a thin client. A privacy-paranoid user may opt to:
- **Leave Layer B side stores on the OSS install.** References on Interpretation events resolve to a "local-only stub" with the content hash preserved. Tamper-evidence still works; the bytes never leave the OSS install's host.
- **Run the read-side capability layer on the OSS install even after lifting.** Vendor reads remain OSS-side; only the aggregate, side stores (excluding Layer B if opted out), and write-side dispatch live in the paid deployment.

Both opt-outs are tenant-config flags applied during the lift workflow.

---

## 10. Cross-cutting concerns

These are designed-in at v0 and exercised meaningfully at v1+. The architecture supports them uniformly across both deployment shapes.

### 10.1 Rate limiting

Adapters expose a `rate_limit_hint` in their manifest (e.g., `5 qps per tenant`, `1 qps per analyst`). The backend's resolver maintains a token-bucket per (adapter, scope) pair and queues calls that would exceed the bucket. Visible in the `CapabilityResult.degradation_notes` when calls are queued; surfaces as `UNAVAILABLE_TRANSIENT` if the bucket is exhausted with the call still pending past a timeout.

### 10.2 Credential resolution

Adapter credentials resolve through a uniform indirection scheme:
- `keychain://<key>` — OS keychain (solo and SaaS read-side-on-laptop deployments)
- `vault://<path>` — HashiCorp Vault or equivalent (SaaS cloud-side adapters)
- `env://<var>` — environment variable (deprecated; for development fixtures only)
- `inline://<value>` — only for development; rejected in production configs

Resolution happens at call time; the resolved bytes are passed to the adapter via stdin (after the JSON-RPC request) and never logged or persisted.

### 10.3 Adapter health probes

Each adapter exposes a `health()` operation; the backend probes on a configurable schedule (default 60s) and on adapter spawn. Health states map to the coverage classification in 03 §6:
- `HEALTHY` → bindings on this adapter are eligible for resolution
- `DEGRADED` → eligible but flagged in `degradation_notes`
- `UNHEALTHY` → bindings on this adapter are skipped; higher-priority bindings on other adapters take over; coverage classification on the call accounts for the skip

Health state is exposed via `list_capabilities` so the LLM tool set is trimmed before the agent reasons over it.

### 10.4 Re-normalization scheduler

When a normalizer's version bumps, historical OcsfEvents may be re-normalized to produce updated ObservedData (03 §4.13). The scheduler is a Temporal workflow (`RenormalizePass`) triggered manually or on normalizer-version-bump events. It scans OcsfEvents matching the target `class_uid` and produces new ObservedData rows; old rows remain valid (immutable in spirit). The pass is checkpointed and cancellable.

### 10.5 Telemetry and observability

The backend emits OpenTelemetry-shaped traces and metrics. Local mode logs to stderr and a rolling file under `~/.reckon/logs/`. SaaS mode forwards to reckon's observability backend (per-tenant scoped; tenant data does not leave its scope; only operational metrics flow to the central dashboard).

A separate, opt-in product-telemetry intake (§11.5) collects anonymized usage signals when the subscriber consents.

### 10.6 Backup and restore

**Bundled-deps configuration.** The bundled Postgres is the single source of truth; standard `pg_dump` produces a complete backup. `reckon backup` and `reckon restore` are CLI subcommands that wrap `pg_dump` / `pg_restore` with the correct schemas and verify the namespace UUID matches before restoring (preventing accidental cross-install restoration).

**Managed-deps configuration.** Standard managed-Postgres backup policies. Tenancy-module deployments additionally produce per-tenant export bundles via the `DecommissionTenant` workflow and any `reckon investigation export` command issued by a tenant admin.

---

## 11. Production-operated surface

The set of services and static resources the paid distribution depends on. In reckon-hosted paid these are reckon-operated; in self-hosted paid the customer operates them, typically from the same Terraform that provisions the rest of the deployment. OSS installs depend on a minimal subset (the signed-bundle distribution surface is mirrorable for air-gap; the relay and email surfaces are only needed if `approver_emails` is configured).

### 11.1 Static surface (CDN)

Signed bundles, distributed via standard CDN, customer installations verify signatures on load:

- **Software releases** — Go binaries (Mac, Windows, Linux) for both OSS and paid distributions; container images for backend-side adapter workers
- **Signed policy bundles** — baseline policies that ship with every install (e.g., the non-removable "AI cannot auto-approve T3" policy from 04 §4.3 Example 2). Customers can layer additional policies on top in tenant config.
- **Fixture corpus** — OCSF scenarios for v0/v1 development and demos (03 §9)
- **Adapter / MCP server registry** — signed manifests for first-party and partner adapters (§6.3)
- **MITRE corpus** — ATT&CK and D3FEND data, refreshed on the operator's schedule, verifiable by signature (~5MB)
- **Documentation, schemas, OpenAPI specs**

Static surface is operationally cheap: standard CDN with signing, no authenticated state, no per-customer logic. For air-gapped customers, the surface is mirrorable — reckon publishes signed bundles to a customer-pulled mirror on a schedule.

### 11.2 Keycloak (authenticated)

Identity provider, deployed per §5.1. In reckon-hosted paid: HA replication + managed Postgres operated by reckon. In self-hosted paid: same software, customer-operated (or reckon-bundled image deployed by customer). In OSS: single-realm bundled. Customer investigation data never reaches Keycloak — only auth identity and roles.

### 11.3 Approval relay (authenticated)

A small stateless service that:
- Accepts approval clicks from email/Slack deep links
- Authenticates the approver against Keycloak (or one-time email-verified flow for non-subscriber peer approvers)
- Renders the approval review panel (the same Next.js component as the SaaS web review)
- Queues approval signals for backend consumption (poll-based; backends fetch `/relay/pending?tenant=...` periodically)

Roughly 200 lines of Go plus the Next.js review panel. Used for OSS `approver_emails` (when configured) and tenancy-module multi-analyst async approvals.

### 11.4 Transactional email

A wrapper around a third-party provider (SES, SendGrid, Postmark) or direct integration. Used for approval emails, invitation emails, security alerts. No customer investigation data in email bodies — only references, action descriptions, and deep links. In reckon-hosted paid: reckon's provider account. In self-hosted paid: customer's provider account.

### 11.5 Optional intake endpoints

- **Telemetry** — anonymized product usage signals when the subscriber consents. Single endpoint, single Postgres. In reckon-hosted paid: runs on reckon's infrastructure, default off. In self-hosted paid: not applicable (customer's deployment doesn't phone home). In OSS: default off.
- **Licensing / entitlement** — bolt-on; not implemented at v0–v1 (see §13.4). When implemented, an endpoint issuing offline-verifiable signed entitlement files (air-gap compatible — no phone-home required).

### 11.6 Web surfaces

- **Tenant-admin portal** (governance module) — user/role management within the tenant's realm; proxies the Keycloak admin API. Replaces raw Keycloak admin console UX for paid customers.
- **Web review panel** — the Next.js component that renders the action review for multi-analyst review and async approval clicks
- **Marketing site, docs site** — standard static + serverless (reckon only; not part of the paid distribution)

---

## 12. Process supervision and packaging

### 12.1 Solo installer

Platform-native installers for macOS (signed pkg), Windows (signed MSI), Linux (deb/rpm + tarball). Each installs:
- The reckon Go binary at a platform-appropriate path
- The bundled Postgres binary (downloaded on first run if not bundled, to keep installer size manageable)
- The bundled Temporal CLI
- A platform-native service definition (launchd / systemd / Windows service)
- The VS Code extension is installed separately from the VS Code marketplace; it discovers the local backend via a well-known port + token

`reckon init` is the first-run command: prompts for OAuth login, generates the tenant namespace UUID, runs initial schema migrations on the bundled Postgres, fetches signed policy and fixture bundles from the CDN, registers the default adapters.

`reckon start` / `stop` / `status` manage the supervised stack.

### 12.2 Update mechanism

`reckon update` checks the CDN for newer signed releases of the binary, adapters, policy bundles, fixture corpus, MITRE corpus. Verifies signatures. Applies updates and restarts services. Pinning to specific versions is supported per resource.

### 12.3 SaaS deployment

Standard cloud-native deployment: stateless reckon-backend workers behind a load balancer, managed Postgres (RLS for multi-tenancy), managed Temporal cluster, S3 for side stores, vault for vendor credentials, Keycloak HA, approval relay as a separate small service, transactional email as third-party. Standard observability stack.

---

## 13. Open-core packaging

reckon ships as open-core. This section defines the architectural shape of that split: what is in the OSS distribution, what is in the two paid modules, how modules load, and the orthogonal axis of operator (customer vs reckon). The open-core line is **operation and governance, never capability or connectors** — and it is structural, not a packaging afterthought.

### 13.1 Two distributions, two binaries from two repos

The open-core split is enforced by a repo boundary, not a folder boundary:

- **OSS distribution.** Public repo `reckon`. The `reckon` binary built from this repo is the engine only: aggregate, capability layer, all adapter classes (MCP, NATIVE_API, CUSTOM, FIXTURE, SOAR_PLAYBOOK), normalizers, action authorization machinery, knowledge service core, reasoning loop, VS Code extension. No paywalled connectors. No paywalled investigative features. Single tenant. Bundled deps (Postgres, Temporal, Keycloak single realm). A single environment investigates fully on the free tier.

- **Paid distribution.** Private repo `reckon-enterprise`, which depends on the public `reckon` repo as a Go module and implements the `reckon/module/` interfaces. The `reckon` binary built from this repo is a *behavioral superset* of the OSS engine: the same code paths plus the loaded paid modules (tenancy, governance, or both). Production-grade dependencies (managed Postgres, managed Temporal, managed Keycloak HA, S3, Vault) are typical but not required — the bundled deps still work; the choice is operational, not architectural.

The repo boundary is the architectural enforcement: the OSS binary has no paid code on disk because the paid code is not in its import graph. The interface contract lives in `reckon/module/` and is implemented in `reckon-enterprise/tenancy/` and `reckon-enterprise/governance/`. Run the paid binary with all `paid.*.enabled: false` and it behaves identically to OSS — same engine, same code paths. The honor-system gate at v0–v1 is config-driven; at v2+ a signed entitlement check joins the config flag. The repo layout is in `implementation/module-layout.md`.

### 13.2 Module inventory

**OSS engine — always present.**
- Investigation aggregate (command handler, event store, projections)
- Capability layer (resolver, all adapter classes, normalizers, identity resolver)
- Knowledge service core (SOP and concluded-investigation summary corpora, retrieval API, lightweight authoring)
- Action authorization machinery (CEL evaluator, policy registry, trust tiers, `ActionLifecycle` and `ReversalSaga` workflows)
- Bundled Keycloak (single realm, single tenant)
- Bundled Postgres + Temporal (via `embedded-postgres-go` + Temporal CLI dev server)
- VS Code extension
- All adapter manifests for first-party connectors, including SOAR_PLAYBOOK bindings

**Tenancy module — paid.**
- `tenant_id` RLS activation on the aggregate, projections, and side stores
- Multi-realm or claim-routed Keycloak configuration
- Per-tenant vault paths for vendor credentials
- Multi-instance OSS-to-paid consolidation lift workflow (sub-path B done properly per §9.2)
- Cross-tenant analyst console
- Tenant lifecycle workflows (`ProvisionTenant`, `SuspendTenant`, `DecommissionTenant`, `LiftSolo`)

**Governance module — paid.**
- Tenant-admin UI proxying the Keycloak admin API
- IdP federation setup helpers and role-mapping templates (Okta, Entra, Google Workspace, Auth0, generic SAML/OIDC)
- SOP and policy signoff queues (the operational surface around `governance_mode: gated`; see §13.3)
- Per-SOP citation/usage analytics
- Auditor read-only export surface (full audit chain, action history, policy evaluation records)
- Compliance audit-log export for SOC 2 and equivalent regimes
- Distribution of customer-authored signed policy bundles beyond the baseline shipped with every install

The two modules are independent: a deployment can activate tenancy without governance, governance without tenancy, or both. Modules detect each other and integrate where they overlap — e.g., the signoff queue is tenant-scoped when tenancy is also active.

### 13.3 Behaviors and roles are core; operational tooling is paid

The roles in §5.4 (`viewer`, `analyst`, `approver`, `senior_approver`, `policy_author`, `policy_signer`, `sop_author`, `sop_signer`, `tenant_admin`, `auditor`, `ti_admin`) are defined in the OSS engine. In an OSS install they work — they exist in Keycloak, they're carried in the JWT, the backend enforces them. What's absent in OSS is the *polished operational surface*:

- Role assignments happen through the bundled Keycloak's admin console — functional but raw.
- The SOP and policy lifecycle has both `lightweight` (write-it-use-it) and `gated` (draft → in-review → published → retired) modes. The mode is a deployment config; both are in the engine. But the gated-mode UX — review queue, signoff history, citation analytics, audit export — is only useful with the governance module's surface.
- Audit data is recorded fully and queryable — but the auditor's export-and-report surface is governance-module territory.

This is the general philosophy: **behaviors and roles are core; the operational tooling around them is the governance module.** It is what lets the OSS install be genuinely useful standalone while keeping the governance module's surface meaningful for deployments operating at scale. A deployment picks `lightweight` or `gated` as its working model; the engine supports both, one at a time.

### 13.4 Module activation and licensing posture

Modules are activated by configuration. At v0–v1 the activation is honor-system: a config flag enables the module. The architectural seam — separately-compilable packages or build tags — is preserved so that a future signed-entitlement check has a single, isolated place to live.

At v2+, the activation gate adds an offline-verifiable signed entitlement file (air-gap compatibility forbids periodic phone-home licensing). The entitlement check fires at module load and refuses activation if the signature is invalid or expired. Adding this check is a small, isolated change — not a refactor — precisely because the module seam is preserved from v0.

The architectural commitment is: keep the module boundary clean. Pricing and licensing terms are independent of this commitment.

### 13.5 Operator is orthogonal to distribution

Who runs the bits is independent of which bits are running.

- **OSS — always customer-operated.** reckon does not host the OSS distribution. The customer runs it on a laptop (the default first-run experience — a single-host install achievable in an afternoon), a server, or anywhere else they choose. The credential-resolution indirection scheme (§10.2) makes laptop-vs-server a config concern (`keychain://` vs `vault://`/`env://`), not a code path.
- **Paid — customer-operated OR reckon-operated.** Same Terraform, same Helm chart, same dependency set, same config schema. The differences are who pays the cloud bill, who's on the pager, which VPC the resources live in. None are architectural.

The architecture supports both paid-operator choices uniformly. §11 (the production-operated surface) describes the services — signed-bundle distribution, approval relay, transactional email, observability — that the paid distribution depends on. In reckon-hosted paid, reckon operates these services. In self-hosted paid, the customer operates them, typically from the same Terraform that provisions the rest of the deployment. reckon's CDN-equivalent for signed bundles is *mirrorable* for self-hosted customers (the air-gap path); the customer's deployment pulls from a local mirror that reckon publishes to on a schedule.

Operator-orthogonality preserves the air-gap / self-hostable path for customers who need it while preserving reckon's ability to offer a managed experience for those who don't. There is no architectural fork between the two.

---

## 14. Companion edits to upstream specs

These are minor edits that land alongside this spec. Each is small and additive; none changes architectural commitments.

### 14.1 01-domain-model.md

**Resolve open question on `x-hypothesis.labels`:** "Labels bind to MITRE ATT&CK technique IDs by convention (e.g., `T1486`, `T1078.004`); freeform values permitted. The agent loop is prompted to label hypotheses with applicable techniques where evident."

**Extend PROVENANCE section:** add `consulted_sops` and `consulted_similar_investigations` as optional fields on Interpretation Layer A. Each is a list of `{id, version, retrieval_score}` references into the knowledge service. Layer B side store extends to retain retrieved snippets keyed by content hash. Detail in 06 §7.

### 14.2 03-capability-layer.md

**New verb category — external case lookup:** `query_external_cases(filter: CaseFilter, window: TimeWindow) -> list<ObservedData>` and `get_external_case_details(case_id: string) -> ObservedData`. Adapters: `thehive`, `servicenow_soc`, `jira_soc`, custom. Output normalized as ObservedData wrapping case references. Same shape as existing verbs.

**Note on MITRE flow:** the existing `indicator_types` field on Indicators emitted by the `detection_finding` normalizer (§4.12) already carries MITRE technique IDs where vendors emit them; this is preserved as the canonical path for technique data into the interpretation layer.

### 14.3 04-action-authorization.md

**Extend `ActionDescriptor` schema** with optional `d3fend_technique` field. Mapping is illustrative (free metadata; not enforced) — the authoritative per-action mapping is 04-action-authorization.md §2.1:

```
host.isolate         d3fend_technique: D3-NI    (Network Isolation)
account.disable      d3fend_technique: D3-AL    (Account Locking)
credential.reset     d3fend_technique: D3-CR    (Credential Revocation)
detection.deploy     d3fend_technique: D3-DA    (Detection Authorship)
ioc.publish_to_misp  d3fend_technique: D3-IDA   (Indicator Distribution)
ioc.publish_to_isac  d3fend_technique: D3-IDA
```

**Extend CEL evaluation context (§4.2):**
```
ctx.sop_guidance.applicable             bool — true if SOP retrieval surfaced relevant guidance
ctx.sop_guidance.recommendation         string — extracted recommendation if SOP guidance is structured
ctx.similarity.has_match                bool — true if recall_similar_investigations returned ≥1 ranked result
ctx.similarity.top_match_outcome        "succeeded" | "failed" | "abandoned" — terminal state of the closest past match
```

These are optional context fields; policies that don't reference them are unaffected. They enable policy patterns like "auto-approve if SOP recommends this action class AND the closest past similar investigation succeeded with the same action."

### 14.4 02-persistence.md

No structural changes. The existing event taxonomy already accommodates the post-conclusion pipeline (07) — the `InvestigationConcluded` event is the trigger for the post-conclusion Temporal workflow; no new event types are required. Cross-investigation linkage events (mentioned as deferred in 02 §8) land with 07.

---

## 15. v0 / v1 / v2+ staging

| Stage | Deployment | Capability surface | Notes |
|---|---|---|---|
| **v0** | OSS only (laptop default) | Read fixtures + write fixture stubs; agent loop functional (interactive client-side); SOPs functional with keyword retrieval. SOAR_PLAYBOOK adapter class shipped with fixture playbooks. | No real integrations. Knowledge service ships with SOP CRUD and lightweight `governance_mode` only; no embeddings yet. Bundled Pg + Temporal + Keycloak. Signed-bundle distribution surface live. Temporal workflows: action lifecycle, reversal, re-normalization, archive, post-conclusion, summary extraction. Cross-investigation similarity is keyword search over `investigation_current` projection. Open-core seam preserved via the two-repo `module/` interface boundary (public `reckon` defines the interfaces; private `reckon-enterprise` implements them — see `implementation/module-layout.md`); no licensing check. |
| **v1** | OSS (laptop and self-hosted multi-user) | Real read integrations (EDR, SIEM, IdP, TI, comms, ticketing, MDM); write-side adapter contract lands; T2/T3 actions live; real SOAR_PLAYBOOK bindings (Tines/Torq/customer-authored) | Cross-cutting concerns (rate limiting, health probes, credential resolution) actively exercised. Knowledge service adds embeddings and post-conclusion summary extraction. MITRE corpus distribution live. **`InvestigationLifecycleWorkflow` lands as the top-level Temporal orchestrator**; v0 child workflows reparent under it. |
| **v2** | OSS + paid distribution (self-hosted and reckon-hosted) | Paid tenancy and governance modules launch. Shared investigation, async approvals via relay, vault-based vendor credentials, BYO IdP federation upstream of Keycloak, gated `governance_mode` UX | Paid distribution goes live in both operator modes. Lift Sub-path A consolidates OSS instances into paid multi-tenant. **`BackgroundHuntWorkflow` and `ScheduledInvestigationWorkflow` land — server-side agent loops with tenant-scoped LLM credentials, separate from per-analyst BYOK.** SOC 2 / compliance work begins for reckon-hosted. Honor-system module activation still in place. |
| **v3+** | (deferred) | MSP / hierarchical tenancy if customer demand justifies; cross-tenant indicator pool; signed offline-verifiable entitlement licensing (replaces honor-system) | None of this is on the v0–v2 roadmap. Each is gated on real customer need. |

---

## 16. Open questions / Deferred to implementation

These are deliberate non-decisions; the architecture accommodates either resolution.

- **Realm-per-tenant vs claim-routed shared realm in Keycloak.** Operational choice, doesn't affect the backend's authorization logic. Per-realm gives stronger isolation and simpler admin scoping; shared-realm-with-claims is operationally simpler at small scale. Pick based on customer size and contract requirements at v2 launch.
- **Default access-token and refresh-token validity.** Proposed defaults: 1h access, 30d refresh. Tunable per tenant and per role; stricter for `tenant_admin` and `policy_signer`.
- **pgvector vs alternatives** for the knowledge service. pgvector is the v0+ default for operational simplicity (already on the bundled Postgres). If retrieval quality at scale demands a dedicated vector engine, the storage interface in 06 is abstracted enough to swap.
- **Per-tenant Temporal namespace scaling cap.** Temporal's namespace primitive scales to the low thousands. If a paid reckon-hosted tenant count exceeds that, sharding across multiple Temporal clusters with a dispatcher layer becomes necessary. Not a v2 concern.
- **Sub-path B (OSS joining an existing paid tenant) default behavior.** v0 default is "personal scratch + write fresh into shared tenant." Confirm against managed/SaaS deployment requirements whether re-id or alias-bridge alternatives are demanded.
- **Telemetry intake schema and consent UX.** What signals to collect, what consent model, retention. Operational call, not an architectural one.
- **Adapter binary distribution mechanism.** Direct CDN download with signature verification at v0. If adapter version churn becomes painful, an OCI-registry-style distribution is a future option without changing the manifest contract.
- **Action-authorization enforcement of "guard against half-finished AI multi-step responses."** Whether to support a "composite action" primitive (a single `x-action` bundling multiple effects, atomic in the audit and authorization sense) or to leave multi-step as the agent loop's responsibility with policy gates on individual actions. v0 defers to the agent loop; revisit if real omissions surface in operation.
- **Per-tenant analytics surface (MTTR, approval latency, reversal rate, throughput, SOP citation analytics).** All metrics are derivable from the event-sourced aggregate — every event carries timestamp, principal, delegate, correlation id, and target set. The data exists from v0. The *surface* (CISO dashboard, team-lead view, analyst self-view) is deferred to governance-module work post-v2; bolt-on, no architectural change required. MTTD is explicitly out of scope (detection happens upstream of reckon's Seed events).
- **Cross-tenant analyst console.** Promised in §13.2 as part of the tenancy module. Detailed surface — cross-tenant MTTR/throughput/reversal rollups for an operator looking across their tenants — deferred to tenancy-module work post-v2. The cross-tenant *aggregation* path is structurally available the moment the tenancy module is on; the dashboard is additive UI over it.
- **Cross-org / industry-benchmark surface (peer comparisons across customer tenants).** Genuinely cross-tenant by definition; requires explicit opt-in, anonymization, and differential-privacy-shaped design so no participating tenant's data is attributable. Deferred to v3+ alongside cross-tenant indicator pool. Not a v0–v2 concern.

---

## 17. Cross-references

- **01-domain-model.md** — every primitive this architecture instantiates: aggregate boundary, actor model, identity, lifecycle, edge types, custom STIX objects
- **02-persistence.md** — event taxonomy, projections, side store mechanics, the optimistic-concurrency property the shared-investigation flow relies on
- **03-capability-layer.md** — read-side verbs, adapter classes, normalizers, identity computation, coverage classification, fixture mechanics
- **04-action-authorization.md** — trust tiers, action types, policy machinery, two-axis evaluation, approval flows, the reversal model
- **08-write-side-actions.md** — the write-side adapter contract this section's `ActionLifecycle` workflow dispatches through
- **06-knowledge-service.md** — SOP corpus and concluded-investigation summary corpus, retrieval API, audit linkage
- **07-post-conclusion-outputs.md** — export bundle, IOC extraction, candidate SOP generation, ticketing handoff, document generation, the post-conclusion Temporal workflow

---

*End of spec.*
