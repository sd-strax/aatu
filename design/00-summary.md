# aatu — Architecture Summary

A starting point for new UX and implementation conversations. Seven detailed specs sit alongside this file; this summary is intentionally short and navigation-oriented. Read this first, then drop into the relevant spec when you need depth.

---

## What aatu is

"Cursor for SOC analysts" — an AI-native investigation environment with vertically-integrated remediation. The pitch: replace playbook-based SOAR with **capability-driven AI assembly conditioned on institutional tribal knowledge**, where every state-changing action is audit-traced from the byte of telemetry that justified it.

Personas: threat hunters and IR responders (not T1/T2 triage).
Workflows: investigation (entity-rooted) and hunting (hypothesis-rooted) — same loop, different entry points.
Differentiator vs. existing SOAR: investigation-engine-with-judgment-applied, not workflow-engine-with-investigation-bolted-on.

---

## How an analyst uses it (the loop)

1. **Open a seed** — alert, entity, or question — in the VS Code extension (primary) or CLI.
2. **AI agent runs the loop**: pulls institutional context (SOPs and similar past investigations) from the knowledge service, calls capability verbs against telemetry tools (EDR, SIEM, IdP, TI, etc.), generates and evidences hypotheses, surfaces sightings.
3. **Analyst watches the reasoning thread** in real time, can intervene, edit hypotheses, propose pivots.
4. **State-changing actions** (host isolate, account suspend, ticket open, IOC publish, detection deploy) flow through trust-tier authorization with manual / auto-policy / two-party approval modes. AI proposes; human (or pre-signed-off policy) disposes.
5. **Conclusion** triggers a Temporal-orchestrated post-conclusion pipeline: signed export bundle, IOC extraction to known-bad list, candidate-SOP draft generation, similarity-based linkage suggestions, optional ticketing handoff, optional industry sharing.
6. **The reasoning thread becomes training material** — for analysts (who watch worked examples) and for the system itself (whose retrieval index gets richer with every concluded investigation).

---

## Architecture in two paragraphs

**Domain.** A single tenant-wide graph with two layers joined by typed edges. Telemetry layer = raw OCSF events, immutable. Interpretation layer = STIX 2.1-shaped objects (entities, observations, judgments, reasoning acts), mutable. An investigation is a STIX Grouping plus four extensions (Seed, Lifecycle, ReasoningThread, ConclusionSlot). Identity is deterministic UUIDv5 within a per-tenant namespace, so cross-tenant id collision is structurally impossible. Two genuinely invented primitives: `x-interpretation` (records reasoning) and `x-action` (state-changing operation). AI is always a delegate, never a principal — every event records a human principal who is responsible.

**Runtime.** Go backend; bundled Postgres and bundled Temporal locally; managed equivalents in SaaS. Investigation aggregate is event-sourced (single Postgres events table, atomic event-append + projection-update). STIX object layer is CRUD with thin history. Capability layer is transport-neutral (MCP / native API / custom / fixture adapters), pure I/O + normalization, served as out-of-process JSON-RPC binaries. Knowledge service holds two corpora (SOPs and concluded-investigation summaries) with pgvector embeddings. **Two execution paths for the agent's reasoning, by design**: interactive synchronous turns run client-side in the VS Code extension with the analyst's BYOK LLM key (key never crosses to backend); async / long-running work (background hunts, scheduled re-runs, post-conclusion pipeline, summary generation, candidate-SOP drafting) runs server-side as Temporal workflows using tenant-scoped LLM credentials. Action dispatch, approval timers, reversal sagas, re-normalization, archive bundling, and the top-level `InvestigationLifecycleWorkflow` (v1+) all run on Temporal. Authentication is aatu-operated Keycloak with JWT-borne roles (no role mirroring in aatu's DB).

---

## Two deployment shapes

| | Solo localhost | Multi-tenant SaaS |
|---|---|---|
| Hosting | Analyst's laptop | aatu-operated cloud |
| Tenants | Personal tenant of one | Many tenants, RLS by `tenant_id` |
| Postgres | Bundled (embedded-postgres-go) | Managed |
| Temporal | Bundled (dev mode, shared Pg) | Managed cluster, per-tenant namespaces |
| Identity | aatu Keycloak (subscriber) | aatu Keycloak (org IdPs federated upstream) |
| Vendor credentials | OS keychain | Vault, per-tenant paths |
| Side stores (Layer B) | Local Pg side tables | S3, per-tenant prefixes |
| Knowledge service | pgvector on bundled Pg | pgvector on managed Pg |
| Multi-analyst | No | Yes (shared investigation) |
| Async approval | Optional via configured `approver_emails` | First-class via approval-relay + email/Slack |
| Vendor read calls | From laptop, per-analyst credentials | Configurable: laptop or cloud worker fleet |
| Vendor write calls | Fixture-only at v0; real on laptop at v1 | Always cloud-side via Temporal workers |

The "lift" from solo to SaaS preserves the analyst's tenant namespace UUID, replays events, and copies side stores. STIX ids stay stable across the lift. This is sub-path A. Sub-path B (joining an existing tenant) defaults to "personal scratch alongside" the new shared tenant.

Per-tenant VM offering: explicitly skipped. Solo or SaaS; nothing in between.

---

## Decisions locked (do not relitigate)

| Domain | Decision |
|---|---|
| Stack | Go everywhere; one binary across both shapes |
| Local Postgres | Bundled |
| Local Temporal | Bundled (dev mode, sharing Pg) |
| Identity | aatu-operated Keycloak; subscribers are native, orgs federate upstream |
| Roles | Live in IdP, carried in JWT; aatu does not cache or mirror roles |
| Token policy | No valid token, no operation (workflow-context exception for Temporal) |
| LLM keys | BYOK; never seen by backend |
| Agent loop | Client-side (VS Code extension); CLI is for domain ops at v0 |
| Adapter packaging | Out-of-process JSON-RPC, MCP-compatible |
| Multi-tenant locally | No; solo is single-tenant |
| Multi-tenant SaaS | Yes, with shared investigation |
| Skip per-tenant VM | Yes (deal-driven later if ever) |
| AI as principal | Never; AI is always a delegate |
| Domain vocabulary | STIX 2.1 (interpretation) + OCSF (telemetry) |
| Domain identity | Deterministic UUIDv5 within per-tenant namespace |
| Two-axis authorization | RBAC gate + 04 action-authorization gate |
| Playbooks | Replaced by AI-assembled responses + RAG-SOP retrieval |
| Knowledge service | Sibling of capability layer, not a member |
| Capability layer | Pure I/O + normalization; reads and writes are symmetric in shape |

---

## The seven specs

| # | Spec | Owns |
|---|---|---|
| 01 | [domain model](01-domain-model.md) | What an investigation IS — primitives, identity, lifecycle, edge types, the actor model |
| 02 | [persistence](02-persistence.md) | How investigation state is stored — event taxonomy, projections, side stores, AI reasoning persistence |
| 03 | [capability layer](03-capability-layer.md) | LLM↔tool surface — verb catalog, adapter classes, normalizers, identity computation, fixture mechanics |
| 04 | [action authorization](04-action-authorization.md) | How actions are proposed, authorized, executed, audited, reversed — trust tiers, two-party, CEL policy engine |
| 05 | [component architecture](05-component-architecture.md) | Component topology, deployment shapes, authn, the lift path, aatu-operated surface |
| 06 | [knowledge service](06-knowledge-service.md) | SOP corpus, concluded-investigation summary corpus, retrieval API, audit linkage, embedding model |
| 07 | [post-conclusion outputs](07-post-conclusion-outputs.md) | Export bundle, IOC extraction, candidate-SOP generation, cross-investigation linkage, ticketing handoff, industry sharing |

Two threads explicitly deferred:
- **Write-side adapter contract** — referenced from 03 §10, 04 §6.1, 02 §3 (`ActionDispatched`); needs to land before any v1 action dispatch code. Symmetric to the read-side contract.
- **Detection authoring tooling** — v2+; data model accommodates it, no new domain primitive needed.

---

## Open for UX work

The architecture is firm; the user-facing surfaces are wide open. UX conversations should focus on:

**Investigation surface**
- Reasoning-thread visualization in VS Code (chronological, branching, foldable Interpretations with rationale + cited evidence)
- Inline action affordances on entities (right-click → "isolate this host," "find similar past cases")
- Coverage projections (MITRE ATT&CK heatmap; "techniques observed in your tenant")
- Pivot panels (entity context, indicator context, similar investigations side-by-side with current)

**Authorization surface**
- T2 single-confirm review panel (action verb + targets + cited evidence + Approve/Reject/Modify)
- T3 typed-challenge panel (analyst types `purge 47 emails`)
- TWO_PARTY flow (primary then secondary, both with typed challenges, presence-aware)
- Async approval landing pages (web app for clicked email/Slack deep links)
- Solo subscriber `approver_emails` configuration
- Multi-analyst action review with `assignee_ref` claim and live presence

**Knowledge surface**
- SOP editor (markdown + structured `applies_to` metadata, draft → review → signoff lifecycle)
- SOP library view (filter by technique, status, last-modified; per-SOP citation analytics)
- Candidate-SOP review queue (post-conclusion-generated drafts pending `sop_author` refinement)
- Similar-investigation drill-down (selected past case loads its concluded report + reasoning thread)

**Lift / onboarding**
- First-run flow (`aatu init` → Keycloak login → namespace UUID generation → fixture seeding → adapter registration)
- Lift-to-SaaS wizard (sub-path A primary; sub-path B as opt-in)
- Tenant admin console (user/role management, adapter configuration, policy review, SOP signoff queues)

**Multi-analyst (SaaS)**
- Presence indicators ("Bob is viewing this investigation," "Sarah is editing this hypothesis")
- Concurrency conflict surfacing ("X just changed this 3s ago — refresh / merge / overwrite")
- Activity feed across the tenant (recent investigations, recent conclusions, recent actions taken)

**Reporting and projections**
- Export bundle viewer (signed bundle imported into a read-only inspection mode)
- Compliance document drafting (templated outputs with author-pending review for LLM-narrated sections)
- Coverage / health dashboards (which adapters are healthy, which techniques have detection coverage, which SOPs are stale)

UX conversations should reference the relevant spec section for constraints. Most surfaces touch [05-component-architecture.md](05-component-architecture.md) for what's running where.

---

## Open for implementation work

The architectural decisions are settled; concrete implementation is wide open. Implementation conversations should focus on:

**Backend skeleton (Go)**
- Process supervisor for solo (Pg + Temporal + aatu-backend)
- HTTP + WebSocket server for IDE/CLI clients
- Aggregate command-handler service (Postgres optimistic concurrency on `(aggregate_id, sequence_no)`)
- Atomic event-append + projection-update pattern
- Authorization middleware: JWT validation + role extraction + two-axis evaluation
- Temporal worker registration (action lifecycle, post-conclusion pipeline, re-normalization, archive bundling, summary extraction)

**Capability layer**
- Resolver: verb → binding → adapter, with priority + preconditions + fall-through
- Adapter runtime: out-of-process JSON-RPC stdio dispatch, health probes, rate limiting, credential resolution
- Normalizer registry (per `class_uid`), versioned, with re-normalization scheduler
- Identity resolver (per-tenant namespace UUID, deterministic UUIDv5, cross-tool stitching)
- Fixture adapter (matches block, scenario loader, delay simulation)

**Knowledge service**
- SOP CRUD + lifecycle (DRAFT → IN_REVIEW → PUBLISHED → RETIRED) + signoff governance
- Investigation summary extraction (`SummarizeForKnowledgeIndex` Temporal workflow)
- Embedding pipeline (bundled local ONNX + BYOK provider opt-in)
- Retrieval API (`/knowledge/recall_sops`, `/knowledge/recall_similar_investigations`)
- Audit linkage (Layer A `consulted_*` fields, Layer B side-store of retrieved snippets)

**Action authorization**
- CEL evaluator integration (`cel-go`)
- Policy registry, signed bundle loader, shadow-mode evaluation
- Action lifecycle workflow (`ActionLifecycle` in Temporal — REQUESTED → APPROVED/PENDING_SECONDARY → EXECUTING → terminal, with retries)
- Reversal saga workflow (`ReversalSaga`)
- Two-party state machine + approver pool resolution

**Agent loop (TypeScript, in extension)**
- BYOK key handling (keychain integration)
- Tool-definition construction from `/capabilities` + `/knowledge/tools`
- LLM dispatch, tool-call routing to backend, transcript accumulation
- Implicit retrieval (SOP + similar-investigation recall at seed time)
- Explicit `recall_sop` and `recall_similar_investigations` tool dispatch
- Final command POST with transcript bytes for hashing

**Identity and auth**
- Keycloak deployment (production realm + subscribers realm + per-tenant realms or claim routing)
- JWT signing-key distribution to backend installations
- Token refresh handling on the client (extension)
- Federated upstream IdP setup (SAML/OIDC) per tenant
- Tenant-admin user-management UI proxying to Keycloak admin API

**Post-conclusion pipeline**
- `PostConclusionPipeline` Temporal workflow
- Export bundle generator (STIX 2.1 bundle + event-stream JSON + Markdown report + signing)
- IOC extraction step + tenant known-bad list integration
- Candidate-SOP generator (LLM-assisted pattern detection over the reasoning thread)
- Linkage suggestion step (calls knowledge service for similarity)
- Templated ticket-creation step (rule engine + Jira/ServiceNow/Linear adapters)

**Distribution / aatu-operated surface**
- CDN: signed binary releases, signed policy bundles, fixture corpus, MITRE corpus, adapter registry
- Approval relay (small Go service: POST endpoint, queue, GET-pending for backends)
- Transactional email integration
- Optional telemetry intake
- Tenant lifecycle workflows (`ProvisionTenant`, `SuspendTenant`, `DecommissionTenant`, `LiftSolo`)

**VS Code extension shell**
- Backend discovery (well-known port + token for solo; URL config for SaaS)
- WebSocket subscription for projection deltas
- Authentication flow (PKCE OAuth → token cache)
- Panels: investigation, action review, SOP editor, knowledge browser, settings

Implementation conversations should reference [05-component-architecture.md](05-component-architecture.md) §3 (solo topology) and §4 (SaaS topology) for the deployment-level shape, then drill into the relevant subsystem spec.

---

## Cross-cutting concerns (designed at v0, exercised at v1+)

These are present in the architecture but only become important in v1+ when real integrations land. Worth being aware of in any implementation conversation:

- **Rate limiting** per adapter / per scope (token-bucket; surfaces in `degradation_notes`)
- **Credential resolution** indirection (`keychain://`, `vault://`, `env://`, `inline://`)
- **Health probes** per adapter, mapping to `coverage` enum values
- **Re-normalization scheduler** (`RenormalizePass` Temporal workflow on normalizer-version bumps)
- **Telemetry / observability** (OpenTelemetry traces and metrics)
- **Backup / restore** (`pg_dump`-shaped for solo; managed for SaaS)

---

## Deferred — out of scope for current conversations

These are deliberate non-priorities. Don't engage with them in v0–v2 conversations:

- Write-side adapter contract (its own thread, but blocks v1 actions)
- Detection authoring as a feature (v2+)
- Multi-analyst on the laptop (v3+ if ever)
- MSP / hierarchical tenancy (v3+ on customer demand)
- Cross-tenant indicator pool (v3+ on customer demand)
- Per-tenant VM hosted offering (deferred indefinitely; only if a deal forces it)
- Mobile app (v3+)
- Forking-as-branching investigations (data model accommodates it; no scheduled work)
- Replay-as-re-execution (replay-as-reading works at v0; re-running is v1+ research)
- Snapshot-based aggregate optimization (only when fold latency demands)
- Cross-process event distribution beyond LISTEN/NOTIFY (v3+ at scale)

---

## v0 / v1 / v2 staging

| Stage | Deployment | Capability surface | Notes |
|---|---|---|---|
| **v0** | Solo localhost only | Read fixtures + write fixture stubs; agent loop functional; SOPs functional with keyword retrieval | No real integrations. Knowledge service has SOP CRUD and basic retrieval, no embeddings. |
| **v1** | Solo localhost | Real read integrations across EDR, SIEM, IdP, TI, comms, ticketing, MDM; write-side adapter contract lands; T2/T3 actions live | Cross-cutting concerns actively exercised. Knowledge service adds embeddings + post-conclusion summaries. |
| **v2** | Solo localhost + multi-tenant SaaS | Both shapes. Shared investigation. Async approvals via aatu relay. Vault-based vendor credentials in SaaS. Federated org IdPs upstream | SaaS deployment goes live. Lift sub-path A becomes a customer-facing flow. SOC 2 / compliance work begins. |
| **v3+** | (deferred) | MSP / hierarchical tenancy; cross-tenant indicator pool; detection authoring tooling | Each gated on real customer need. |

---

## How to use this summary

In a new conversation:

1. Paste this file or reference it as `design/00-summary.md`.
2. State explicitly what the conversation is about: "we're working on the UX for the action review panel" or "we're implementing the capability resolver."
3. The architecture above is the substrate. The seven specs are the depth. Most UX/implementation questions fold into either "what should this look like?" (UX) or "how should this be built?" (implementation), with the architectural shape already settled.
4. If a conversation surfaces a question that the existing specs answer, link to the spec section instead of relitigating.
5. If a conversation surfaces a genuinely new architectural question, that's a signal to spawn a new spec or extend an existing one — not to redesign in-conversation.

---

## Quick orientation pointers

- **What is an investigation?** [01-domain-model.md INVESTIGATION](01-domain-model.md) section.
- **What does the AI agent see when it starts?** Tool definitions from `list_capabilities` ([03-capability-layer.md §2.8](03-capability-layer.md)) plus `recall_sop` and `recall_similar_investigations` from [06-knowledge-service.md §5](06-knowledge-service.md).
- **What's the friction model for state-changing actions?** Two gates: RBAC ([05-component-architecture.md §5.4](05-component-architecture.md)) + action authorization ([04-action-authorization.md](04-action-authorization.md)).
- **What happens when an investigation concludes?** [07-post-conclusion-outputs.md §9](07-post-conclusion-outputs.md) describes the Temporal pipeline.
- **How does an analyst go from solo to SaaS?** [05-component-architecture.md §9](05-component-architecture.md), sub-path A primary.
- **Why "no playbooks"?** Because the AI assembles responses from primitives, conditioned on retrieved SOPs. SOPs are *judgment* (prose), not *control flow* (code). [06-knowledge-service.md §1](06-knowledge-service.md) frames it.
- **Why MITRE ATT&CK / D3FEND?** Industry lingua franca, structurally useful as labeling spine, near-zero implementation cost. [01-domain-model.md OPEN QUESTIONS Closed](01-domain-model.md), [04-action-authorization.md §2.1](04-action-authorization.md).
- **What's the audit story for an action?** Every action traces to its evidence, to the OcsfEvent that grounded it, with hashes on retrieved knowledge for tamper-evidence. [04-action-authorization.md §9 Audit trail](04-action-authorization.md).

---

*End of summary.*
