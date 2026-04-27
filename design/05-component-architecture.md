# Component Architecture — Spec

## Project context

"Cursor for SOC analysts" — AI-native investigation environment with a dynamically-assembled remediation surface. Substrate: VS Code extension (primary), CLI (secondary), Go backend, Next.js web (review panels and approval relay surfaces in SaaS), transport-neutral capability layer for tool federation, and a knowledge service holding institutional context (SOPs, concluded-investigation summaries). Personas v0: threat hunters and IR responders. Workflows v0: investigation (entity-rooted) and hunting (hypothesis-rooted). v0 ships against OCSF fixtures; v1 ships real integrations alongside the fixture corpus; v2 launches the multi-tenant SaaS.

This spec defines the component topology, deployment shapes, authentication, the lift path between deployments, and the operated surface aatu (the company) runs centrally. It assumes the four upstream specs as authoritative input.

## Thread scope

- Component topology of the same Go binary across two deployment shapes
- Solo localhost: process supervision, bundled Postgres + Temporal, agent-loop placement, vendor credential handling
- Multi-tenant SaaS: managed data plane, federated identity, shared investigation, async approval surface
- Authentication and authorization: aatu-operated Keycloak, JWT-borne roles, two-axis evaluation
- The lift path from solo to SaaS, including identity continuity and namespace handling
- The aatu-operated static and service surface (CDN, IdP, approval relay, email, telemetry, MITRE corpus)
- Cross-cutting concerns designed-in at v0 and exercised at v1: rate limiting, credential resolution, health probes, re-normalization scheduling, observability

## Out of scope

- The investigation domain model itself (01-domain-model.md)
- Persistence model (02-persistence.md)
- Capability layer verbs, normalization, identity rules (03-capability-layer.md)
- Action authorization machinery (04-action-authorization.md)
- The knowledge service internals — corpora, embeddings, retrieval mechanics, authoring (06-knowledge-service.md)
- Post-conclusion outputs — export bundle, IOC extraction, candidate SOPs, ticketing handoff (07-post-conclusion-outputs.md)
- The write-side adapter contract — referenced where it matters; full design is its own deferred thread (03-capability-layer.md §10)
- Detection authoring as a feature (deferred to v2+; data model accommodates it)
- UI rendering specifics

---

## 1. Decision summary

| Concern | Decision | Reasoning |
|---|---|---|
| Backend language | Go everywhere | Single binary distribution, low cold-start, healthy MCP / cloud-native ecosystem; STIX/OCSF library landscape is workable in any language given the spec's deviations and the codegen-from-schema approach to OCSF |
| Deployment shapes | Solo localhost + multi-tenant SaaS | Skip per-tenant VM tier — competes with SaaS for the same buyer with worse economics for both |
| Local Postgres | Bundled (`embedded-postgres-go`) | Analyst UX; same Postgres also hosts Temporal persistence and the local pgvector for the knowledge service |
| Local Temporal | Bundled (Temporal CLI dev server, Postgres-backed) | Eliminates handrolled task-queue plumbing for action expiry, dispatch retries, reversal sagas, re-normalization, archive bundling, and the post-conclusion workflow |
| Agent loop | Client-side (extension/CLI) | BYOK LLM key never crosses to the backend; same loop code points at localhost or cloud backend identically |
| LLM provider | BYOK | Per-analyst keys via OS keychain locally; per-analyst keys via aatu's vault in SaaS, never aatu-hosted inference at v0–v2 |
| Adapter packaging | Out-of-process JSON-RPC, MCP-compatible | Polyglot adapter authoring; mature MCP ecosystem reuse; in-process Go plugins explicitly rejected |
| Knowledge service | New service alongside capability layer | Hosts SOPs and concluded-investigation summaries; LLM-facing context retrieval, not telemetry production |
| Identity provider | aatu-operated Keycloak | Authoritative for both modes; solo subscribers are native users, SaaS orgs federate their IdPs upstream |
| Authorization roles | Live in IdP, carried in JWT | aatu does not cache or mirror roles; tenant admin role changes propagate on next token refresh |
| Token policy | No valid token, no operation | No grace period for client-initiated commands; long-running Temporal workflows carry the initiating principal in workflow context |
| Vendor credentials | Orthogonal to user identity | OS keychain locally; per-tenant vault paths in SaaS; never visible to user JWTs or the extension |
| Action layer | Same adapter pattern as reads | Symmetric write-side; remediation, ticketing, comms, TI publication, IT operations all slot in as more action types and more adapters |

---

## 2. Architectural commitments

These follow from the upstream specs and the decisions above. They are load-bearing across the rest of this spec and the dependent threads.

**1. Two deployment shapes, one binary.** The same Go backend artifact runs in solo localhost mode and in multi-tenant SaaS mode. Deployment-mode is a configuration dimension, not a code-path dimension. The aggregate, capability resolver, normalizer, identity resolver, policy engine, knowledge service, and Temporal worker are identical across shapes. What differs is what's wired up: Keycloak realm vs. native user, vault paths vs. OS keychain, S3 side store vs. local table, multi-analyst WebSocket fan-out vs. single-analyst direct WebSocket, etc.

**2. Local-first by construction.** Solo localhost runs with zero aatu data-plane involvement. Customer investigation data — events, STIX nodes, OcsfEvents, transcripts, SOPs — never leaves the laptop unless the analyst lifts to SaaS. The aatu-operated surface that solo mode depends on is limited to: aatu's Keycloak (for auth), aatu's CDN (for binary, policy, fixture, MITRE, adapter-registry distribution), and optional approval-relay + transactional email (only when the solo subscriber configures `approver_emails`). Telemetry and licensing intakes, if any, are opt-in.

**3. Identity is aatu's, always.** Both deployment shapes authenticate against aatu's Keycloak. There is no anonymous or local-OS-only identity model. Solo subscribers are native aatu IdP users; SaaS org members federate from their corporate IdP upstream into aatu's Keycloak. Every event written records a principal whose identity was verified against aatu's IdP at command time.

**4. Authorization is two-axis.** Per-request authorization runs in two gates: an RBAC gate evaluated against JWT claims (does this principal hold the role required to attempt this kind of operation?), and an action-authorization gate per 04-action-authorization.md (given that the principal can attempt it, does policy auto-approve, require two-party, or deny?). Solo subscribers collapse Gate 1 trivially because they hold every role in their personal tenant; Gate 2 still applies and the AI delegate constraints remain in force.

**5. The capability layer is symmetric across reads and writes.** Read-side verbs and write-side action types share the same binding/adapter/parameter-mapping structure. An adapter is one or more JSON-RPC operations served by an out-of-process binary that aatu spawns. Adding a remediation tool — EDR, MDM, IdP, ticketing, comms, TI platform, or anything else — is "register an adapter, add bindings, declare an action descriptor." No structural change. The write-side contract is its own deferred thread (03-capability-layer.md §10) but the architecture is symmetric and known.

**6. Knowledge service is a sibling, not a member, of the capability layer.** Capability layer outputs are world-facing observations: OcsfEvents and STIX nodes with telemetry provenance. Knowledge service outputs are internal context: SOPs the LLM consults during reasoning, similar past investigations the LLM cites in rationale. Keeping them separate preserves the capability layer's pure-I/O property and gives the knowledge service its own retention, privacy, and audit story.

**7. The agent loop runs client-side. BYOK keys never cross to the backend.** The VS Code extension (or the future CLI agent surface) holds the analyst's LLM key in the OS keychain. It builds tool definitions from the backend's `/capabilities` endpoint plus the knowledge service's `/knowledge/tools` endpoint, calls the LLM directly, dispatches tool calls to the backend over authenticated HTTP, and posts the resulting Interpretation command together with the transcript bytes for hashing and side-store linkage. The backend never sees the LLM key in either deployment shape.

**8. Tenant-scoped by construction; multi-tenant only in SaaS.** Per the per-tenant namespace UUID rule from 01-domain-model.md §3 and §5, every tenant — solo or SaaS — has its own immutable namespace UUID assigned at creation. Cross-tenant identity collision is structurally impossible. Solo mode is a tenant of one; SaaS mode is many tenants on shared infrastructure with row-level security as defense-in-depth on top of the namespace property.

---

## 3. Solo localhost topology

### 3.1 Process model

A single supervisor process brings up three managed components on the analyst's laptop:

```
aatu start
  ├── postgres            (embedded; persistence for aggregate, Temporal,
  │                        knowledge service, side stores, projections)
  ├── temporal            (dev mode; Postgres-backed; same Pg instance,
  │                        separate database)
  └── aatu-backend        (Go: aggregate command handler, capability
                           resolver, knowledge service, Temporal worker
                           registered for action / archive / re-normalize
                           / post-conclusion workflows, HTTP+WS server)
```

`aatu start` runs the supervisor in the foreground or as a launchd / systemd / Windows service depending on platform. `aatu stop` performs an orderly shutdown. `aatu status` reports component health. The supervisor is responsible for cascading restarts (if Temporal exits, restart it; if Postgres exits, surface a fatal error — Postgres restarts mid-session corrupt the in-flight transactions in unpleasant ways, fail fast).

### 3.2 Postgres

Bundled via the standard embedded-Postgres pattern (`fergusstrange/embedded-postgres` or equivalent). The supervisor downloads the appropriate Postgres binary on first run if not already present. Data lives under `~/.aatu/pg/`.

Schemas / databases on the same instance:
- `aatu_main` — investigation events, STIX object store, projections, side stores (`ai_tool_calls`, `ai_transcripts`)
- `aatu_temporal` — Temporal persistence
- `aatu_knowledge` — SOP repository, concluded-investigation summary index, pgvector embeddings (see 06)

`pgvector` is required for the knowledge service. The bundled Postgres ships with the extension preinstalled; no analyst-facing setup. If a future deployment context demands an alternative (Postgres distributions without pgvector availability), the knowledge service's storage interface is abstracted enough to swap.

### 3.3 Temporal

Bundled as the Temporal CLI dev server, configured to use `aatu_temporal` on the bundled Postgres. The aatu-backend process registers a Temporal worker on the same `aatu` task queue. The workflow inventory expands by stage:

**v0 workflows — durable mechanics with no agent reasoning:**
- `ActionLifecycle(action_id)` — sleeps until expiry or signal-on-approval; on approval, dispatches; handles the retry budget per 04 §6.1; emits the chain of `Action*` events
- `ReversalSaga(reversing_action_id)` — runs the reversal action; on success, posts `ActionReversed` against the original
- `RenormalizePass(class_uid, version_from, version_to)` — long-running batch, cancellable, checkpointed
- `ArchiveInvestigation(grouping_id)` — bundle, sign, write to archive target
- `PostConclusionPipeline(grouping_id)` — runs the IOC extraction, candidate-SOP generation, optional ticketing handoff (see 07)
- `SummarizeForKnowledgeIndex(grouping_id)` — extracts the structured summary and embeddings written into the knowledge service (see 06)

**v1 addition — top-level investigation orchestrator:**
- `InvestigationLifecycleWorkflow(grouping_id)` — spawned at `InvestigationCreated`, lives until `InvestigationArchived`. Owns investigation-level orchestration state (active hypotheses summary, pending actions, scheduled hunts, lifecycle timers like "warn analyst if no activity for 7 days," "auto-archive if concluded for 90 days"). Receives signals on major events (interactive turn produced an Interpretation, action requested, conclusion requested). Spawns and supervises the v0 child workflows — `ActionLifecycle`, `ReversalSaga`, `PostConclusionPipeline` are reparented as children rather than independent root workflows. Survives extension restarts, laptop reboots, and — in SaaS — multi-analyst handoff. **The lifecycle workflow does not drive interactive analyst turns**; it tracks them as observed signals while the extension owns the interactive loop.

**v2 additions — server-side agent loops for async work:**
- `BackgroundHuntWorkflow(investigation_ref, hunt_spec)` — analyst kicks off "find all signs of lateral movement in the past 72 hours" and goes home. The workflow drives its own agent loop server-side using a tenant-scoped LLM credential (vault path in SaaS, OS keychain in solo) — separate from per-analyst BYOK keys. Dispatches tool calls through the same capability layer; records Interpretations against the parent investigation; notifies the analyst on completion via Slack / email / IDE notification.
- `ScheduledInvestigationWorkflow(spec)` — cron-shaped periodic re-runs ("re-run this hunt every 6 hours and alert on new findings"); same agent-loop substrate as `BackgroundHuntWorkflow`.

The Temporal worker pool runs in the same OS process as the aatu-backend; there is no separate worker binary. This keeps the local install at three managed processes (Postgres, Temporal server, aatu-backend) rather than four. v1 and v2 additions do not change the process count; they're additional registered workflows on the same worker.

### 3.4 Agent loop and capability adapters

**Interactive vs async execution boundary.** The agent's reasoning runs in two places by design:

- **Interactive synchronous turns** (analyst types, AI responds, tools dispatch in real time) run **client-side in the VS Code extension**. The extension holds the analyst's BYOK LLM key in the OS keychain; the LLM call goes from the extension directly to the provider; the backend never sees the LLM key in this path.
- **Async / long-running agent work** (background hunts at v2+, scheduled re-runs at v2+, post-conclusion summary generation, candidate-SOP drafting) runs **server-side as a Temporal workflow**, using **tenant-scoped LLM credentials** (vault path in SaaS, OS keychain in solo) — a separate credential from per-analyst BYOK keys.

Why two paths:
- Interactive turns need sub-second token streaming and the lowest-latency dispatch possible. Temporal activity overhead is fine for minutes-to-hours work, less fine for back-and-forth turns.
- Async work needs durability — the IDE may not be open, the laptop may be closed, the analyst may have handed off to a colleague. State has to live somewhere outside the extension process. Temporal is exactly that.
- The credential separation is deliberate: per-analyst BYOK keys stay analyst-private and are never used by server-side workflows. Server-side workflows use tenant-configured credentials, which the tenant admin can scope, audit, and rotate independently.

The two paths share the same capability layer, the same knowledge service, the same authorization gates, the same aggregate. They write Interpretations to the same reasoning thread. Audit is uniform: principal recorded on every Interpretation, delegate recorded as the AI agent (whether running client-side or server-side), provenance recorded on every output.

**Interactive turn mechanics.** The VS Code extension (or CLI when it grows an agent surface, post-v0) holds the BYOK LLM key in the OS keychain. On session start it:
1. Authenticates against aatu's Keycloak via PKCE OAuth flow, caches the token
2. Calls `/capabilities` on the local backend to fetch the capability descriptor list, trimmed to verbs whose tenant config resolves to a healthy binding
3. Calls `/knowledge/tools` to fetch the knowledge-service tool descriptors (SOP recall, similar-investigation recall)
4. Constructs LLM tool definitions from the union; system prompt includes aatu's reasoning conventions and the implicit-retrieval results for the current investigation context

When the LLM emits a tool call, the extension dispatches it to the backend at `/capability/<verb>` or `/knowledge/<op>` (HTTP POST, JWT in `Authorization` header), feeds the result back to the LLM, repeats. When the loop terminates, the extension posts the final Interpretation command together with the transcript bytes to `/interpretations`; the backend hashes the bytes, writes the side-store row, and appends the event in one Postgres transaction.

Capability adapters run as out-of-process binaries spawned by the backend. The backend speaks JSON-RPC over stdio to each adapter; the contract is MCP-compatible by default but does not require an MCP server (any binary that accepts the contract works). First-party adapters ship as separate Go binaries in the same release; third-party can be any language.

### 3.5 Vendor credentials

Stored in the OS keychain (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux). The adapter receives a `credentials_ref: keychain://<key>` path in its operation parameters, resolves the secret on demand from the keychain, and never persists the plaintext outside the per-call invocation. When the adapter exits, the secret leaves memory.

### 3.6 Network dependencies

Solo localhost is local-first, not offline-only. Required network reachability:
- **aatu Keycloak** — for initial auth and periodic token refresh. Bounded offline tolerance: access-token validity (default 1h) for absolute disconnect; refresh-token validity (default 30d) for reconnect-after-disconnect.
- **aatu CDN** — for software updates, signed policy bundles, fixture corpus updates, MITRE corpus updates, adapter registry. Pull-on-startup with a fallback to last-cached.
- **aatu approval relay + transactional email** — only when the solo subscriber has configured `approver_emails` and a TWO_PARTY policy fires. Otherwise unused.
- **Vendor APIs** (in v1+) — direct from laptop to vendor for read-side capability calls; per-analyst credentials via OS keychain.
- **LLM provider** (BYOK) — extension calls the analyst's chosen provider directly; never via aatu.

The aatu-backend process itself does not require outbound network for normal investigation work once the token is fresh and cached static surfaces are loaded. An analyst running a hunt against fixtures on a plane works fine until the access token expires.

### 3.7 Tenant model

Solo mode has exactly one tenant: the subscriber's personal tenant. Namespace UUID generated at `aatu init` and persisted in `aatu_main.tenants`. Immutable thereafter. The principal recorded on every event is the aatu-IdP-issued user id, carried in the JWT.

Multi-tenant on the laptop is explicitly out of scope at v0–v1. An MSP analyst working multiple customer tenants does so by lifting to SaaS or running multiple `aatu` installations under separate user profiles; no shared-instance multi-tenancy locally.

---

## 4. Multi-tenant SaaS topology

### 4.1 Process model

Stateless aatu-backend workers behind a load balancer, each running the same Go binary as the local install with deployment-mode = `saas`. Workers register the same Temporal worker on per-tenant task queues. State lives in:

- **Managed Postgres** — `aatu_main` with row-level security policies keyed on `tenant_id`; per-tenant namespace UUIDs as defense-in-depth (cross-tenant id collision is structurally impossible regardless of RLS)
- **Managed Temporal cluster** — per-tenant namespaces; workflow ids include `tenant_id` prefix for visibility filtering
- **S3 (or equivalent object store)** — `ai_transcripts` and `ai_tool_calls` bytes, per-tenant prefixes, lifecycle policies for retention
- **Knowledge service store** — managed Postgres + pgvector, per-tenant schemas or row-level isolation; same data shape as solo
- **Vault** — vendor credentials per tenant, accessed by adapter workers; never visible to user JWTs or the extension

### 4.2 Capability adapter deployment

Three configurations supported, selected per-tenant by config:

**Read-side: laptop.** The default. Per-analyst vendor credentials in OS keychain; adapter binaries spawned by a thin local helper process that the extension manages. The cloud backend never sees the analyst's vendor credentials. Same shape as solo.

**Read-side: cloud.** For tenants that require vendor credentials off analyst laptops (governance, IP allowlisting on vendor APIs, rate-limit pooling across analysts). Adapter binaries run as cloud-side workers; analyst's extension calls the cloud backend, which dispatches to the worker fleet. Vendor credentials live in vault, accessed only by the worker.

**Write-side: always cloud-side at v0–v2.** Action dispatch runs as a Temporal workflow on the cloud worker fleet. Vendor write credentials live in vault, accessed only during the workflow's execute step. The `adapter_request_id` correlated in `ActionDispatched` events (02-persistence.md §3) is the Temporal workflow id. This is the deployment site that justifies the deferred write-side adapter contract (03 §10).

### 4.3 Shared investigation

When more than one analyst in a tenant subscribes to the same investigation, the cloud backend fans projection deltas out via WebSocket. Mechanism: aggregate writes commit in Postgres, post-commit hook fires `NOTIFY` keyed on `(tenant_id, investigation_id)`, a backend service `LISTEN`s and pushes deltas to all WS connections subscribed to that investigation.

Concurrency model:
- **Append-only paths** (recording an Interpretation, adding a Sighting, requesting an action) are collision-free by construction — each write is a new event, no contention.
- **Status changes on shared nodes** (hypothesis status, member add/remove on the Grouping) use the aggregate's optimistic concurrency on `(aggregate_id, sequence_no)`. On conflict, the second writer's IDE pulls the latest projection, surfaces "X just changed this N seconds ago," and the analyst decides whether to retry, edit, or move on.
- **Action review collisions** are handled by the `assignee_ref` field already in the spec (04 §5.4). First analyst to claim → first to approve/reject wins.
- **Presence indicators** ("Sarah is currently viewing this investigation," "Bob is editing hypothesis-3") are ephemeral WebSocket signals, not aggregate events. Stored in a Redis-shaped in-memory store keyed on investigation_id + user_id, expiring on disconnect.

### 4.4 Async approval surface

TWO_PARTY actions and any AI-proposed T2/T3 that the requesting analyst hasn't picked up route through the approval relay surface:
- Approver receives an email (via aatu's transactional email path) with a signed deep link
- Click lands on aatu's web approval app, which authenticates against aatu's Keycloak and renders the same review panel the IDE shows
- Approval signal is queued in the relay; backend polls or receives a push and processes the approval
- The approver may or may not be a subscriber to that tenant — if they're not, the email-based flow uses one-time email-verified deep-link auth scoped to the specific action only (cannot read anything else, cannot perform any other action)

This same mechanism powers solo `approver_emails` (when a solo subscriber configures peer review) and SaaS multi-analyst `secondary_approver_pool` (drawn from Keycloak users in the tenant's realm).

### 4.5 Tenant lifecycle

Provisioning, suspension, decommission, and migration are Temporal workflows running in aatu's operations namespace (separate from any customer tenant namespace):

- `ProvisionTenant(...)` — assign namespace UUID, create realm or claim mapping, allocate vault path, seed default policies, configure default adapters, create tenant_admin user
- `SuspendTenant(tenant_id)` — read-only mode; no aggregate writes accepted
- `DecommissionTenant(tenant_id)` — export → delete; final export bundle delivered to a customer-specified target
- `LiftSolo(source_user_id, target_tenant_id, mode)` — handles the lift path (§9)

---

## 5. Authentication and authorization

### 5.1 aatu-operated Keycloak

aatu (the company) operates a Keycloak deployment as the identity provider for both deployment shapes. This is real authenticated infrastructure, not a static distribution surface. Every backend command-handler RPC validates a JWT issued by this Keycloak.

**Realms and federation.**
- **Solo subscribers** are native Keycloak users in a `subscribers` realm (or equivalent partition). Standard email/password + MFA, OIDC PKCE flow from the extension.
- **SaaS org members** authenticate via federation. Each org tenant has either its own realm (stronger isolation) or its own group + tenant claim (operationally simpler at small scale) within a shared realm. Org IdPs (Okta, Entra, Google Workspace, Auth0, generic SAML/OIDC) federate upstream into aatu's Keycloak. Org users sign in through their corporate IdP; aatu's Keycloak mints the resulting JWT.

The realm-vs-claim choice is an operational decision that does not affect the backend's authorization logic — JWT verification and claim extraction are uniform.

**Tenant management.**
- Solo subscriber's "tenant" is implicit and singular; the JWT's `tenant_id` claim equals the subscriber's personal tenant id, generated at sign-up.
- SaaS tenant admins (a role within the tenant) manage their own users in their realm/group via aatu's tenant-admin web UI, which proxies to Keycloak's admin API. They do not have access to other tenants. aatu staff have admin access to tenant lifecycle (create/suspend/decommission) but not to tenant data.

### 5.2 JWT structure

Standard OIDC with these aatu-specific claims:

```
sub               aatu-issued user id (stable across federation)
email             user's verified email
tenant_id         active tenant for this session (solo: personal tenant;
                  SaaS: org tenant the user is acting in)
tenant_memberships array of {tenant_id, roles[]} — all tenants the user
                  belongs to, used by the IDE to allow tenant switching
roles             array of role names valid for the active tenant_id
                  (drawn from the canonical role set in §5.4)
delegate_kind     "HUMAN" (the aatu-IdP-issued user is always a human;
                  AI agents are delegates, not principals)
exp, iat, nbf     standard
```

Roles live in Keycloak as group memberships within the tenant's realm. `roles` claim is computed at token issuance from the user's current group memberships. **aatu does not cache or mirror roles in its application database.** A tenant admin removing a user from a role takes effect on the next token refresh.

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

**Solo subscribers hold every role in their personal tenant by default.** Their JWT carries the union. RBAC Gate 1 always passes; the action-authorization Gate 2 (04's machinery) still applies, including the AI-delegate constraints that produce friction proportional to risk regardless of how many roles the principal holds.

### 5.5 Two-axis evaluation

Every state-changing operation passes through two gates:

**Gate 1 — RBAC (role-based, JWT-borne).** Does the principal hold the role required to attempt this kind of operation? Cheap, evaluated first, sourced from JWT claims. Failure: 403 with the missing role surfaced.

**Gate 2 — Action authorization (04's machinery).** Given that the principal can attempt it, does policy auto-approve, require manual confirmation, require two-party, or deny? Includes blast-radius escalator, AI-delegate constraints, evidence-derivation checks, and any tenant-authored CEL policies. CEL evaluation context (04 §4.2) is built from the aggregate state at evaluation time.

Both gates must pass. The reasoning thread records both outcomes; the policy evaluation is captured in the `PolicyEvaluated` event (02 §3) regardless of result.

### 5.6 Tool credentials are orthogonal to user identity

User identity (aatu IdP, JWT) and tool credentials (vendor API keys, OAuth tokens for Splunk / CrowdStrike / Okta / etc.) are entirely separate auth layers. They never appear in the same envelope.

- **User auth** (JWT) gates *every* backend RPC and every aggregate write. Tells the backend who is making the request.
- **Tool auth** (per-adapter credential references) gates outbound calls to vendor systems. Tells the vendor system that aatu (acting on behalf of an analyst) is authorized to read or write.

Solo: user auth via aatu Keycloak; tool credentials in OS keychain.
SaaS: user auth via aatu Keycloak (federated); tool credentials in vault, scoped per tenant.

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

The write-side adapter contract (operation declaration, idempotency key, `adapter_request_id` correlation) is the subject of its own deferred thread (03 §10). This spec assumes its eventual landing without specifying it.

### 6.3 Adapter discovery

Adapters are discovered through signed manifests distributed via aatu's CDN (the adapter registry; §11). Each manifest declares: adapter name, version, `AdapterClass` (MCP / NATIVE_API / CUSTOM / FIXTURE), supported operations, parameter schemas, supported action types (for write-side adapters), and a verification signature.

Tenants pin specific adapter versions in their config. Pinning is per-tenant; there is no global version. Adapter binaries are downloaded on demand and cached locally; manifests verify against the aatu CDN's signing key before any binary is invoked.

### 6.4 Verb and action-type registration

The verb catalog (03 §2) and the action-type manifest (04 §2) are extensible without spec changes. New verbs and action types are registered by:
1. Implementing an adapter that supports the corresponding operation
2. Declaring a `CapabilityDescriptor` (verb) or `ActionDescriptor` (action type) in the adapter's manifest
3. Adding bindings in tenant config

The descriptor declares: name, input/output schemas, intent description (consumed by the LLM), default tier (action types only), reversibility mapping (action types only), and optional D3FEND technique (action types only; see §13 companion edits).

`list_capabilities` (03 §2.8) and the analogous `list_action_types` walk the registered descriptors and trim by tenant configuration and adapter health, so the LLM only sees what's currently usable.

---

## 7. Knowledge service deployment

The knowledge service runs as a sibling to the capability layer, hosted in the same backend process. It exposes two corpora — SOPs and concluded-investigation summaries — through a unified retrieval API consumed by the agent loop.

Storage:
- **Solo**: `aatu_knowledge` schema on the bundled Postgres with pgvector; SOP content, summary content, embeddings all local.
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

Slack/email/mobile deep links route through the approval relay (§11). The approver clicks, lands on aatu's web approval surface authenticated against their Keycloak identity (or one-time email-verified link if they're not a subscriber), reviews the same panel the IDE shows, and approves or rejects. The relay queues the decision and the backend processes it on the next poll.

### 8.5 Presence

Per-investigation presence (which users are currently viewing, who's editing what) is ephemeral. Stored in an in-memory map keyed on `(tenant_id, investigation_id)` with TTL on disconnect. WebSocket presence frames flow to all subscribers. Not persisted to the aggregate.

---

## 9. The lift path

The lift moves a solo subscriber's investigation work from their laptop into a SaaS-tenant aggregate. It is not a rewrite — it is a replay of the same events into a different deployment of the same backend. Identity continuity is the property that makes it clean.

### 9.1 Sub-path A — solo lifts to a fresh tenant of one (primary)

The default lift. The subscriber already has an aatu IdP identity; their personal tenant exists with namespace UUID `N_local`. The "lift" is a re-pointing of where their tenant's data lives.

Steps:
1. Provision a SaaS tenant with namespace UUID = `N_local`. The same UUID is preserved; every STIX id remains stable.
2. Replay the local `investigation_events` stream into the cloud aggregate (`INSERT ... ON CONFLICT DO NOTHING` on `(aggregate_id, sequence_no)`).
3. Copy `stix_*` rows and `stix_edges` rows for this tenant.
4. Upload Layer B side stores by content hash: `ai_tool_calls` and `ai_transcripts` rows transfer to S3, references on Interpretation events resolve through the new store.
5. Copy SOP repository rows and concluded-investigation summary index.
6. Repoint the IDE config at the SaaS endpoint. The user's existing JWT is still valid; on next refresh, the `tenant_id` claim points at the SaaS tenant.

The solo subscriber's data is identical, just hosted differently. The principal recorded on every event is unchanged. No aliasing edges, no re-id, no migration drama.

### 9.2 Sub-path B — solo joins an existing tenant

Harder, because the subscriber's local namespace `N_local` differs from the existing tenant's `N_tenant`. v0 default behavior:

**The local data parks as a personal-scratch read-only side.** The subscriber retains read access to their personal tenant alongside their new shared tenant; their JWT carries `tenant_memberships` for both. They write only into the new shared tenant going forward. Their local investigations do not pollute the shared tenant's namespace.

Two heavier alternatives, available on request post-v0:
- **Re-id** — walk every STIX node in the migrated investigations, recompute UUIDv5 under `N_tenant`, rewrite events accordingly. Heavy but produces a clean unified namespace.
- **Alias-bridge** — migrate with original `N_local` ids and write `aliases` edges (01 EDGE TYPES) between `N_local` and `N_tenant` entities where they refer to the same real-world thing. Cheaper than re-id, but the alias graph is queried on every cross-tenant pivot.

Sub-path B's UX matters more than its implementation; getting it wrong means analysts won't lift, they'll restart. v0 doesn't ship Sub-path B at all. v2 ships the personal-scratch default.

### 9.3 What stays on the laptop after a lift

By default, all data migrates to SaaS and the local install becomes a thin client. A privacy-paranoid subscriber may opt to:
- **Leave Layer B side stores on the laptop.** References on Interpretation events resolve to a "local-only stub" with the content hash preserved. Tamper-evidence still works; the bytes never leave the laptop.
- **Run the read-side capability layer locally even after lifting.** Vendor reads remain laptop-side; only the aggregate, side stores (excluding Layer B if opted out), and write-side dispatch live in SaaS.

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

The backend emits OpenTelemetry-shaped traces and metrics. Local mode logs to stderr and a rolling file under `~/.aatu/logs/`. SaaS mode forwards to aatu's observability backend (per-tenant scoped; tenant data does not leave its scope; only operational metrics flow to the central dashboard).

A separate, opt-in product-telemetry intake (§11.5) collects anonymized usage signals when the subscriber consents.

### 10.6 Backup and restore

**Solo.** The bundled Postgres is the single source of truth; standard `pg_dump` produces a complete backup. `aatu backup` and `aatu restore` are CLI subcommands that wrap `pg_dump` / `pg_restore` with the correct schemas and verify the namespace UUID matches before restoring (preventing accidental cross-install restoration).

**SaaS.** Standard managed-Postgres backup policies plus per-tenant export bundles via the `DecommissionTenant` workflow and any `aatu investigation export` command issued by a tenant admin.

---

## 11. aatu-operated surface

The total set of services and static resources aatu (the company) operates centrally.

### 11.1 Static surface (CDN)

Signed bundles, distributed via standard CDN, customer installations verify signatures on load:

- **Software releases** — Go binaries for solo (Mac, Windows, Linux); cloud-worker images for SaaS internal use
- **Signed policy bundles** — baseline policies that ship with every install (e.g., the non-removable "AI cannot auto-approve T3" policy from 04 §4.3 Example 2). Customers can layer additional policies on top in tenant config.
- **Fixture corpus** — OCSF scenarios for v0/v1 development and demos (03 §9)
- **Adapter / MCP server registry** — signed manifests for first-party and partner adapters (§6.3)
- **MITRE corpus** — ATT&CK and D3FEND data, refreshed on aatu's schedule, verifiable by signature (~5MB)
- **Documentation, schemas, OpenAPI specs**

Static surface is operationally cheap: standard CDN with signing, no authenticated state, no per-customer logic.

### 11.2 Keycloak (authenticated)

aatu-operated identity provider. Required for both deployment shapes. Realms organize subscribers and SaaS tenants; federated upstream IdPs handle org members. Standard Keycloak admin/operator deployment with HA replication and managed Postgres.

This is the only customer-data-adjacent service required for solo mode (and even then, customer investigation data never reaches it — only auth identity and roles).

### 11.3 Approval relay (authenticated)

A small stateless service that:
- Accepts approval clicks from email/Slack deep links
- Authenticates the approver against Keycloak (or one-time email-verified flow for non-subscriber peer approvers)
- Renders the approval review panel (the same Next.js component as the SaaS web review)
- Queues approval signals for backend consumption (poll-based; backends fetch `/relay/pending?tenant=...` periodically)

Roughly 200 lines of Go plus the Next.js review panel. Used for solo-mode `approver_emails` and SaaS multi-analyst async approvals.

### 11.4 Transactional email

Either an aatu-operated wrapper around a third-party (SES, SendGrid, Postmark) or direct integration. Used for approval emails, invitation emails, security alerts. No customer investigation data in email bodies — only references, action descriptions, and deep links.

### 11.5 Optional intake endpoints

- **Telemetry** — anonymized product usage signals when the subscriber consents. Single endpoint, single Postgres, runs on aatu's infrastructure. Not on customer infrastructure. Default off in solo; configurable in SaaS per tenant.
- **Licensing / entitlement** — if the product is commercial, an endpoint that issues short-lived signed entitlement claims. Cached on the customer side.

### 11.6 Web surfaces

- **Customer portal** — account management, subscription, tenant admin tasks (for tenant_admins; user/role management within their realm)
- **Web review panel** — the Next.js component that renders the action review for SaaS multi-analyst review and async approval clicks
- **Marketing site, docs site** — standard static + serverless

---

## 12. Process supervision and packaging

### 12.1 Solo installer

Platform-native installers for macOS (signed pkg), Windows (signed MSI), Linux (deb/rpm + tarball). Each installs:
- The aatu Go binary at a platform-appropriate path
- The bundled Postgres binary (downloaded on first run if not bundled, to keep installer size manageable)
- The bundled Temporal CLI
- A platform-native service definition (launchd / systemd / Windows service)
- The VS Code extension is installed separately from the VS Code marketplace; it discovers the local backend via a well-known port + token

`aatu init` is the first-run command: prompts for OAuth login, generates the tenant namespace UUID, runs initial schema migrations on the bundled Postgres, fetches signed policy and fixture bundles from the CDN, registers the default adapters.

`aatu start` / `stop` / `status` manage the supervised stack.

### 12.2 Update mechanism

`aatu update` checks the CDN for newer signed releases of the binary, adapters, policy bundles, fixture corpus, MITRE corpus. Verifies signatures. Applies updates and restarts services. Pinning to specific versions is supported per resource.

### 12.3 SaaS deployment

Standard cloud-native deployment: stateless aatu-backend workers behind a load balancer, managed Postgres (RLS for multi-tenancy), managed Temporal cluster, S3 for side stores, vault for vendor credentials, Keycloak HA, approval relay as a separate small service, transactional email as third-party. Standard observability stack.

---

## 13. Companion edits to upstream specs

These are minor edits that land alongside this spec. Each is small and additive; none changes architectural commitments.

### 13.1 01-domain-model.md

**Resolve open question on `x-hypothesis.labels`:** "Labels bind to MITRE ATT&CK technique IDs by convention (e.g., `T1486`, `T1078.004`); freeform values permitted. The agent loop is prompted to label hypotheses with applicable techniques where evident."

**Extend PROVENANCE section:** add `consulted_sops` and `consulted_similar_investigations` as optional fields on Interpretation Layer A. Each is a list of `{id, version, retrieval_score}` references into the knowledge service. Layer B side store extends to retain retrieved snippets keyed by content hash. Detail in 06 §7.

### 13.2 03-capability-layer.md

**New verb category — external case lookup:** `query_external_cases(filter: CaseFilter, window: TimeWindow) -> list<ObservedData>` and `get_external_case_details(case_id: string) -> ObservedData`. Adapters: `thehive`, `servicenow_soc`, `jira_soc`, custom. Output normalized as ObservedData wrapping case references. Same shape as existing verbs.

**Note on MITRE flow:** the existing `indicator_types` field on Indicators emitted by the `detection_finding` normalizer (§4.12) already carries MITRE technique IDs where vendors emit them; this is preserved as the canonical path for technique data into the interpretation layer.

### 13.3 04-action-authorization.md

**Extend `ActionDescriptor` schema** with optional `d3fend_technique` field. Mapping is illustrative (free metadata; not enforced):

```
host.isolate         d3fend_technique: D3-NTI   (Network Traffic Isolation)
account.suspend      d3fend_technique: D3-AL    (Account Locking)
credential.reset     d3fend_technique: D3-CR    (Credential Rotation)
detection.deploy     d3fend_technique: D3-DA    (Detection Authorship)
ioc.publish          d3fend_technique: D3-IDA   (Indicator Distribution)
```

**Extend CEL evaluation context (§4.2):**
```
ctx.sop_guidance.applicable             bool — true if SOP retrieval surfaced relevant guidance
ctx.sop_guidance.recommendation         string — extracted recommendation if SOP guidance is structured
ctx.similarity.has_match                bool — true if recall_similar_investigations returned ≥1 ranked result
ctx.similarity.top_match_outcome        "succeeded" | "failed" | "abandoned" — terminal state of the closest past match
```

These are optional context fields; policies that don't reference them are unaffected. They enable policy patterns like "auto-approve if SOP recommends this action class AND the closest past similar investigation succeeded with the same action."

### 13.4 02-persistence.md

No structural changes. The existing event taxonomy already accommodates the post-conclusion pipeline (07) — the `InvestigationConcluded` event is the trigger for the post-conclusion Temporal workflow; no new event types are required. Cross-investigation linkage events (mentioned as deferred in 02 §8) land with 07.

---

## 14. v0 / v1 / v2+ staging

| Stage | Deployment | Capability surface | Notes |
|---|---|---|---|
| **v0** | Solo localhost only | Read fixtures + write fixture stubs; agent loop functional (interactive client-side); SOPs functional with keyword retrieval | No real integrations. Knowledge service ships with SOP CRUD and basic retrieval; no embeddings yet. Bundled Pg + Temporal. aatu Keycloak in production for solo subscribers. CDN distributing signed bundles. Temporal workflows: action lifecycle, reversal, re-normalization, archive, post-conclusion, summary extraction. Cross-investigation similarity is keyword search over `investigation_current` projection. |
| **v1** | Solo localhost | Real read integrations (EDR, SIEM, IdP, TI, comms, ticketing, MDM); write-side adapter contract lands; T2/T3 actions live for solo subscribers | Cross-cutting concerns (rate limiting, health probes, credential resolution) actively exercised. Knowledge service adds embeddings and post-conclusion summary extraction. MITRE corpus distribution live. **`InvestigationLifecycleWorkflow` lands as the top-level Temporal orchestrator**; v0 child workflows reparent under it. |
| **v2** | Solo localhost + multi-tenant SaaS | Both shapes. Shared investigation. Async approvals via aatu relay. Vault-based vendor credentials in SaaS. Federated org IdPs upstream of aatu Keycloak | This is when the SaaS deployment goes live. Lift Sub-path A becomes a customer-facing flow. **`BackgroundHuntWorkflow` and `ScheduledInvestigationWorkflow` land — server-side agent loops with tenant-scoped LLM credentials, separate from per-analyst BYOK.** SOC 2 / compliance work begins. |
| **v3+** | (deferred) | MSP / hierarchical tenancy if customer demand justifies; cross-tenant indicator pool; single-tenant hosted only if a deal forces it | None of this is on the v0–v2 roadmap. Each is gated on real customer need. |

---

## 15. Open questions / Deferred to implementation

These are deliberate non-decisions; the architecture accommodates either resolution.

- **Realm-per-tenant vs claim-routed shared realm in Keycloak.** Operational choice, doesn't affect the backend's authorization logic. Per-realm gives stronger isolation and simpler admin scoping; shared-realm-with-claims is operationally simpler at small scale. Pick based on customer size and contract requirements at v2 launch.
- **Default access-token and refresh-token validity.** Proposed defaults: 1h access, 30d refresh. Tunable per tenant and per role; stricter for `tenant_admin` and `policy_signer`.
- **pgvector vs alternatives** for the knowledge service. pgvector is the v0+ default for operational simplicity (already on the bundled Postgres). If retrieval quality at scale demands a dedicated vector engine, the storage interface in 06 is abstracted enough to swap.
- **Per-tenant Temporal namespace scaling cap.** Temporal's namespace primitive scales to the low thousands. If SaaS tenant count exceeds that, sharding across multiple Temporal clusters with a dispatcher layer becomes necessary. Not a v2 concern.
- **Sub-path B (solo joining existing tenant) default behavior.** v0 default is "personal scratch + write fresh into shared tenant." Confirm with first SaaS customers whether re-id or alias-bridge alternatives are demanded.
- **Telemetry intake schema and consent UX.** What signals to collect, what consent model, retention. Operational call, not an architectural one.
- **Adapter binary distribution mechanism.** Direct CDN download with signature verification at v0. If adapter version churn becomes painful, an OCI-registry-style distribution is a future option without changing the manifest contract.
- **Action-authorization enforcement of "guard against half-finished AI multi-step responses."** Whether to support a "composite action" primitive (a single `x-action` bundling multiple effects, atomic in the audit and authorization sense) or to leave multi-step as the agent loop's responsibility with policy gates on individual actions. v0 defers to the agent loop; revisit if real omissions surface in operation.

---

## 16. Cross-references

- **01-domain-model.md** — every primitive this architecture instantiates: aggregate boundary, actor model, identity, lifecycle, edge types, custom STIX objects
- **02-persistence.md** — event taxonomy, projections, side store mechanics, the optimistic-concurrency property the shared-investigation flow relies on
- **03-capability-layer.md** — verbs, adapter classes, normalizers, identity computation, coverage classification, fixture mechanics, the deferred write-side adapter contract
- **04-action-authorization.md** — trust tiers, action types, policy machinery, two-axis evaluation, approval flows, the reversal model
- **06-knowledge-service.md** — SOP corpus and concluded-investigation summary corpus, retrieval API, audit linkage
- **07-post-conclusion-outputs.md** — export bundle, IOC extraction, candidate SOP generation, ticketing handoff, document generation, the post-conclusion Temporal workflow

---

*End of spec.*
