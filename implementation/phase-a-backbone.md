# Phase A — Backbone

**Calendar:** Month 1–3
**Headcount:** Founder/architect + 2 senior Go backend engineers + designer
**Done when:** Bundled deps boot under the supervisor; the aggregate persists events and replays them into projections; JWT-authenticated RPC works end-to-end; paid-module package boundary is in place and proven.

## Scope

### A.1 Module layout and package boundary (Week 1)

**Owner:** Founder/architect or first senior hire.
**Reference:** `module-layout.md`.

Lay down the directory structure, the `oss/module` interfaces, the cmd-side wireup, and the config loader. No business logic. Single Go test proves the seam switches correctly between OSS and paid distributions.

**Done bar:**
- Repo compiles, `go test ./...` passes (empty tests OK).
- `aatu version` runs.
- A config flag flips a no-op switch demonstrably.
- Decision on Option A vs B build configuration recorded in `decisions.md`.

### A.2 Bundled deps supervisor (Weeks 2–4)

**Owner:** Backend engineer #1.
**Reference:** `design/05-component-architecture.md §3.1, §12.1`.

`aatu start` brings up four managed components:

```
aatu start
  ├── postgres            (embedded; pgvector preinstalled)
  ├── temporal            (dev mode, Pg-backed, separate DB)
  ├── keycloak            (single realm, OIDC issuer)
  └── aatu-backend        (HTTP+WS server, Temporal worker, aggregate)
```

- `aatu stop` performs orderly shutdown.
- `aatu status` reports health.
- Cascading restart rules: Temporal exit → restart; Postgres exit → fatal (mid-session corruption risk).
- Platform service hooks drafted (launchd / systemd / Windows service) but not yet polished.

**Done bar:** Demo on macOS + Linux. `aatu start` → all healthy → kill Temporal → restarts cleanly → `aatu stop` shuts everything down. Postgres data persists across restarts.

### A.3 Postgres schema bootstrap (Week 4)

**Owner:** Backend engineer #1.

Three databases on the bundled Pg instance per `05 §3.2`:
- `aatu_main` — investigation events, STIX object store, projections, side stores
- `aatu_temporal` — Temporal persistence
- `aatu_knowledge` — SOPs, summaries, pgvector embeddings (Phase C concern, schema only at A)

Migration tooling: pick one (`migrate` / `goose` / `sqlc-driven`) and stick with it. Record in `decisions.md`.

**Done bar:** Fresh `aatu init` creates all three DBs with migrations applied. Re-running is idempotent.

### A.4 Event-sourced aggregate (Weeks 4–9)

**Owner:** Senior backend engineer #2 + founder/architect.
**Reference:** `design/02-persistence.md` — the canonical event taxonomy, projection model, optimistic concurrency rules.

The investigation aggregate is the spine. It owns:
- Single `investigation_events` table (no event-sourcing framework — direct Postgres)
- Optimistic concurrency on `(aggregate_id, sequence_no)`
- Atomic event-append + projection-update in one transaction
- Projection rebuild from event stream
- Command handler with envelope validation (actor, JWT, command kind)

**Subscope:**
- A.4.1 Event store (table, insert path, optimistic check)
- A.4.2 Projection runner (currently in-process; consider later if pull-based)
- A.4.3 First projections: `investigation_current` (basic state), `investigation_thread` (Interpretation ordering)
- A.4.4 Command handler skeleton (no actual commands yet beyond `CreateInvestigation`)
- A.4.5 Replay from cold (rebuild projection state from events)

**Done bar:** A handcrafted `CreateInvestigation` command persists an event, the projection updates, the projection is queryable. Replay from cold produces identical projection state. A second command on the same aggregate at stale `sequence_no` is rejected.

### A.5 Authentication and authorization middleware (Weeks 5–8, parallel)

**Owner:** Senior backend engineer #1.
**Reference:** `design/05-component-architecture.md §5`.

- JWT validation against Keycloak's signing keys
- Claim extraction: `sub`, `tenant_id`, `roles`, `delegate_kind`
- Two-axis evaluation skeleton: Gate 1 (RBAC) middleware on the HTTP server; Gate 2 (action authorization) stubbed for Phase C
- Keycloak realm bootstrap: a single `aatu` realm with the canonical role set (`05 §5.4`), test user, OIDC client for the extension

**Done bar:** Run `aatu start`, hit an HTTP endpoint without a token → 401. With a valid token → 200. Without the required role → 403 with the missing role surfaced.

### A.6 HTTP+WS server skeleton (Weeks 6–9)

**Owner:** Senior backend engineer #1.

- HTTP router with the auth middleware in front
- WebSocket endpoint for projection deltas (subscription model wired but no fan-out yet — fan-out lands in Phase D)
- Health endpoint
- Basic OpenAPI scaffolding

**Done bar:** WebSocket connection authenticates at handshake, drops on token expiry. HTTP endpoints surface investigations from the projection store.

### A.7 Temporal worker registration (Weeks 8–10)

**Owner:** Backend engineer #1.

- Register a Temporal worker in-process on the `aatu` task queue per `05 §3.3`
- Skeleton workflows registered (empty bodies) so Phase C can fill them: `ActionLifecycle`, `ReversalSaga`, `RenormalizePass`, `ArchiveInvestigation`, `PostConclusionPipeline`, `SummarizeForKnowledgeIndex`
- A trivial test workflow that fires from a command handler proves the wireup works

**Done bar:** Workflow execution from command-handler → Temporal → side effect → result returned via signal. Visible in Temporal Web UI.

### A.8 Telemetry, logging, observability (Weeks 9–12)

**Owner:** Backend engineer #1.

- Structured logging with levels, contextual fields
- OpenTelemetry trace setup (no exporter wired yet for v0; just the API)
- Metrics scaffolding (Prometheus-shape; expose `/metrics` endpoint)
- Local mode: rolling file logs under `~/.aatu/logs/`

**Done bar:** A request through the system produces a trace with spans across the HTTP handler, command handler, projection update.

## What Phase A does NOT do

- No actual capability layer (Phase B)
- No actual action authorization machinery (Phase C)
- No knowledge service beyond schema (Phase C)
- No agent loop (Phase D)
- No surface beyond raw HTTP/WS (Phase D)
- No real adapters (Phase E+)
- No paid module implementations (Phase I)

## Done bar for Phase A

A backend engineer can:
1. `aatu init` and `aatu start` on a clean macOS or Linux box
2. Authenticate against the bundled Keycloak
3. Issue a `CreateInvestigation` command via authenticated HTTP
4. See the event persisted in `investigation_events`
5. See the projection updated in `investigation_current`
6. Subscribe to a WebSocket and see the projection delta
7. Replay events from scratch and get an identical projection
8. Hit Temporal Web UI and see worker registered with empty workflow stubs
9. Run `go test ./...` and see all tests pass
10. Run the same binary in `deployment.mode: paid, paid.tenancy.enabled: true` and see the stub log "tenancy module enabled but not implemented" without crashing

That's the spine. Phase B starts adding the capability layer on top.

## Risks for Phase A

- **Aggregate design getting tangled with framework choice.** Don't use an event-sourcing framework; direct Postgres is what the spec calls for. Resist abstraction.
- **Keycloak operational complexity.** The bundled deployment is single-realm and small; don't over-engineer. Phase A doesn't need federation or multi-realm.
- **Temporal version pinning.** Pin to a specific Temporal version that works with the dev server; drift here causes the worst kinds of intermittent test failures.

## Cross-references

- `design/02-persistence.md` — the canonical event taxonomy and projection model
- `design/05-component-architecture.md §3, §5, §10, §12` — runtime topology, auth, observability, packaging
- `module-layout.md` — package boundary that Phase A implements
- `roadmap.md` — Phase A's place in the broader plan
