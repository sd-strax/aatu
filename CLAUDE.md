# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository nature

This repo is the **reckon OSS engine** — design specifications today, code starting Week 1 of Phase A. Currently private on GitHub; goes public at Phase H. **Treat every edit as if it's already public.**

Paid modules and commercial strategy live in the separate private repo `reckon-enterprise` (`github.com/sd-strax/reckon-enterprise`). That repo depends on this one as a Go module and implements the `module/` interfaces; this repo has zero awareness of it. The repo boundary is the architectural enforcement of the open-core split.

See "Public OSS posture" below — it is load-bearing for every edit.

## The product (reckon)

"Cursor for SOC analysts" — an AI-native investigation environment for threat hunters and IR responders (not T1/T2 triage). Substrate: **VS Code extension (primary), CLI (secondary), Go backend, transport-neutral capability layer for tool federation** (adapter classes: MCP, NATIVE_API, CUSTOM, FIXTURE, SOAR_PLAYBOOK; see `design/03-capability-layer.md` §5.4). v0 prototype runs against OCSF fixtures via the fixture adapter, not real tenants.

Two workflows, same loop, different entry points: **investigation** (entity-rooted) and **hunt** (hypothesis-rooted).

## The four specs and how they fan in

The specs are not independent — they reference each other and each declares its own scope and out-of-scope items. Treat them as a single coupled design.

| Spec | Owns | Depends on | Flagged contributions to others |
|---|---|---|---|
| `design/01-domain-model.md` | What an investigation IS | — (foundational) | Defines all primitives the others build on |
| `design/02-persistence.md` | How investigation state is stored | domain model (authoritative) | Event taxonomy, AI reasoning persistence layers |
| `design/04-action-authorization.md` | Action authorization, trust tiers | domain model | Adds 7 values to `interpretation_type` enum; new `x-action` primitive; new `reverses` edge type |
| `design/03-capability-layer.md` | LLM↔tool **read** surface (verbs, adapters, normalization) | domain model | Identity computation rules; deviates from strict STIX 2.1 for `process`, `email-addr`, `user-account` |

The other specs (`05` component architecture, `06` knowledge service, `07` post-conclusion outputs, `08` write-side actions) build on these four. **`08-write-side-actions.md` is the write-side twin of `03`** — it owns the `request_action` tool, action descriptors/bindings, the write adapter contract, and the idempotency model; `03` is read-only. `02`/`04`/`05`/`07` reference `08` for action dispatch.

When changing one spec, scan the others for cross-references. `04-action-authorization.md` §10 explicitly lists what it adds back to the domain model; `03-capability-layer.md` §7 explicitly notes its STIX deviations; `08-write-side-actions.md` §0 lists what it owns vs. what `04`/`02`/`05` keep. These are the seams.

## Architectural commitments (load-bearing across specs)

These are decisions that have been ruled out of re-litigation in `01-domain-model.md`. Don't propose changes to them without explicit user direction:

- **Two-layer graph.** Telemetry layer = raw OCSF events, immutable. Interpretation layer = STIX-shaped objects, mutable. Joined by typed edges, never by embedding.
- **STIX 2.1 vocabulary** for the interpretation layer; **OCSF** for telemetry payloads. Adopted, not invented.
- **Identity is deterministic UUIDv5** (STIX rules). Same entity → same id across producers and investigations. Aliasing is an explicit edge, never a destructive merge.
- **Investigation = STIX Grouping + four extensions** (Seed, Lifecycle, ReasoningThread, ConclusionSlot).
- **`x-interpretation` is the only invented primitive** in the domain model. Hypotheses, predictions, findings are outputs of Interpretations, not separate primitives. (`04-action-authorization.md` adds `x-action` as a sibling, with explicit justification.)
- **Investigation aggregate is event-sourced; everything else is CRUD + thin history.** Postgres single events table, no ES framework. Atomic event-append + projection-update in one transaction.
- **AI is a delegate, never a principal.** Every event records a human principal; `actor.delegate` captures the AI. Authorization is the *intersection* of principal permissions and delegate policy.
- **Capability layer is pure I/O + normalization.** It does not reason, never produces `x-interpretation`, always emits `derivation_mode = DIRECT`. Only exception: detection_finding normalizer (`03-capability-layer.md` §4.12).
- **Blast radius, not action verb, drives the trust tier.** T2→T3 escalator at >10 distinct targets is non-negotiable in code, only adjustable.
- **Open core: paid layers on OSS, no overlap.** OSS engine lives in `reckon` (public-bound); paid modules live in a separate private `reckon-enterprise` repo that depends on `reckon` as a Go module and implements its `module/` interfaces. OSS has zero awareness of paid; the repo boundary enforces this. See `implementation/module-layout.md`.

## Public OSS posture

This repo is destined to be public OSS. Every edit must respect that. The following kinds of content do **not** belong here — they belong in `reckon-enterprise`:

- **Buyer profiles** ("MSSP," "in-house SOC," "the buyer pays per...")
- **Conversion economics** (revenue framing, conversion events, pricing/licensing terms beyond "licensing is bolt-on")
- **Commercial commitments** ("the product won't," "no third conversion hook")
- **Team-shape framing** (founder, Claude Code, Claude Design, hunter, contractor, hiring, calendar weeks/months)
- **Customer-specific context** (design partners by name, customer pull anecdotes, internal stakeholder names)
- **Competitive positioning vs SOAR/EDR/SIEM vendors by name** (generic capability comparisons are fine)

What stays here: architectural facts — what the codebase does, how it's structured, the rationale for the tradeoffs a contributor would need to understand.

**When in doubt, write the sentence in `reckon-enterprise`** and surface only the architectural distillation here, if any survives.

A pre-commit hook lands in Week 1 alongside Claude Code workflow setup (per `reckon-enterprise/30-day-plan.md` item 1) to catch obvious commercial keywords on commit. It is a backstop; the discipline lives here.

## Conventions in the prose

- **"v0"** means the mock-fixtures prototype, not a shipping version. Many decisions are explicitly deferred to v1+ and called out as such — preserve those deferrals when editing.
- **Custom STIX objects** use the `x-` prefix per STIX convention: `x-hypothesis`, `x-prediction`, `x-action`, `x-host`, `x-registry-key`, `x-scheduled-task`, `x-group`, `x-interpretation`.
- **"Adopted vs invented"** sections (e.g., `01-domain-model.md`) are load-bearing — they justify why something isn't a new primitive. Don't invent without updating these.
- Specs end with **"Open questions" / "Deferred to v1+"** sections that are deliberate non-decisions; the model accommodates either resolution. Treat these as part of the design, not as TODOs.

## Working in this repo

- When adding a new spec, follow the existing structure: framing/scope → out-of-scope → numbered sections → end-of-spec marker. Cross-reference other specs with section numbers (e.g., "see §4.3"), not page numbers.
- Engineering planning (roadmap, 30-day plan, decisions log, risk register, phase-by-phase scope) lives in `reckon-enterprise` because it's framed around team shape, calendar, and commercial context. Architectural seam docs (`implementation/module-layout.md`) live here because they describe the codebase any contributor would see.
- Cross-references go OSS → OSS only. **Do not reference `reckon-enterprise` paths from any file in this repo.** If you find yourself wanting to, the content you're describing probably belongs over there, and what's in this repo should stand on its own architectural merit.

## Go conventions

We adopt industry-standard public Go conventions rather than maintaining our own style guide. Read these in order:

1. **[Google Go Style Guide](https://google.github.io/styleguide/go/)** — canonical reference. Style Guide + Style Decisions + Best Practices.
2. **[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)** — the actual review checklist.
3. **[Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)** — supplementary; especially the mutex placement and error wrapping sections.
4. **`implementation/reckon-patterns.md`** — the small set of patterns specific to this codebase that the public guides don't address. ~5–6 patterns total. Read once; cite from new code as needed.

`make lint` runs `golangci-lint` with a config (`.golangci.yml`) tuned to enforce most of the above mechanically — `staticcheck`, `errcheck`, `gosec`, `revive`, `gocritic`, `govet`, `bodyclose`, `errorlint`, `unused`. `make ci` (lint + test + build) is the pre-commit / pre-PR check.

When extending the code, prefer references to the public guides over re-arguing style locally. When a project-specific pattern emerges three+ times, add it to `reckon-patterns.md`.

## Commands

`make help` lists everything. The ones you'll reach for:

- `make build` — builds both binaries to `bin/`: `reckon` (CLI/supervisor) and `reckon-backend`.
- `make test` — fast suite: `go test -race -short ./...`. The `-short` flag skips the slow embedded-Postgres/Temporal/Keycloak lifecycle tests (those download and boot real subprocess binaries). Use this loop while developing.
- `make test-all` — full suite including the embedded-deps lifecycle tests (`go test -race -count=1 ./...`); ~60s warm, several minutes cold. Run before a PR that touches `supervisor/`.
- `make lint` — `golangci-lint run ./...` (requires `brew install golangci-lint`).
- `make ci` — lint + fast tests + build. The pre-commit / pre-PR gate.
- `make ci-full` — lint + full tests + build. Pre-release.
- `make hooks` — installs the OSS-leak pre-commit hook (`git config core.hooksPath .githooks/`). Run once after clone.

Run a single test: `go test -race -run TestName ./aggregate/` (drop `-short` if it's a lifecycle test guarded by `testing.Short()`).

The repo is the `reckon` module (Go 1.25). There is no README; `AGENTS.md` just points back here.

## Code architecture (Phase A)

The code is younger than the specs — the remaining skeletons with a `doc.go` stating which phase fills them in are `action/` (Phase C) and `knowledge/` (Phase C/G). The wired-up spine today is the supervisor, the runtime/module seam, the event-sourced aggregate, the auth gates, the Temporal worker (`temporal/`, workflow bodies still Phase C+), and the observability layer (`telemetry/`). Phase B is in progress: `identity/` is built; `capability/` has the adapter contract and fixture adapter, with normalizers and the verb resolver still to land.

**Two binaries, one shared runtime.** `cmd/reckon` is the CLI/supervisor (`start`/`stop`/`status`/`check`/`version`); the whole stack is assembled in `runtime.serve` (`runtime.Run` = activate modules + serve; `runtime.Preflight` = activate only, backing the `check` command). `cmd/reckon-backend` is a ~20-line `main` that injects an OSS `module.Registry` (disabled stubs) into `runtime.Run`. **`runtime.Run` + a `ModuleBuilder` closure is the only place OSS and paid binaries diverge** — this is the architectural enforcement of the open-core split. The paid binary (in `reckon-enterprise`) mirrors `cmd/reckon-backend` with a builder that returns real `module.Tenancy`/`module.Governance` implementations. OSS always uses `module.DisabledTenancy`/`DisabledGovernance`; if a config sets `paid.*` keys against an OSS binary, `runtime.Run` warns and continues.

**Supervisor (`supervisor/`).** Manages the bundled-deps stack as ordered `Component`s: Postgres → Temporal → Keycloak → Temporal-worker → Backend. Each implements the `Component` interface (`Name`/`Start`/`Stop`/`Health`); components hold their lifecycle state under a mutex because `Health` runs concurrently with watcher-driven `Stop`/`Start`. Start in registration order, stop in reverse. `RestartPolicy` is `FatalOnExit` (Postgres — unclean exit risks corruption) or `RestartOnExit` (everything else); `Supervisor.Run` starts a per-component watcher goroutine that polls health and applies the policy (budgeted restarts in a sliding window, escalation to fatal on exhaustion). Postgres/Temporal/Keycloak are real embedded subprocess binaries downloaded on first run — this is why the lifecycle tests are slow and `-short`-gated.

**Event-sourced aggregate (`aggregate/`).** The investigation aggregate is the *only* event-sourced thing; everything else is CRUD + thin history (an architectural commitment, see above). No ES framework — a single Postgres `events` table. The core invariant: `Handler.Handle` runs command→events translation, event-append, and every projector's `Apply` **inside one transaction** (`handler.go`). The Handler loads the stream in-tx, `foldState` folds it into current state, and `applyCommand` is a pure function (envelope + command + folded state → events). Optimistic concurrency via the `(aggregate_id, sequence_no)` primary key — a lost race returns `ErrConcurrent` and callers reload+retry. `Projector`s apply in-tx so the read model can never disagree with the event log; `Reset`+replay rebuilds projections from scratch, always ordered by `(aggregate_id, sequence_no)` — never by `occurred_at`, which is caller-supplied wall-clock time with no monotonicity guarantee. **Phase C.1** added the `x-action` lifecycle here (`04 §3`, `action.go`): x-actions are aggregate-internal (not in the external STIX store), driven by seven `action.*` events whose status is a projection (`action_current`), each transition paired with an `action-*` Interpretation. Two guards live at the command handler — the actor/approver invariant (`actor.principal` must equal the recorded approver) and AI write-protection (`Actor.Kind == AI_DELEGATED` may `RequestAction` but never approve/reject/expire) — enforced at the same layer as the OCC check so no alternate code path bypasses them. Dispatch/result/reversal events (`action.dispatched`/`resulted`/`reversed`) are defined and folded but emitted by the Temporal `ActionLifecycle` workflow in C.4.

**Auth: two gates (`authz/`).** Gate 1 (RBAC) is live — `authz.Verifier` validates Keycloak JWTs against the realm's JWKS (discovered via OIDC `.well-known`), `RequireAuth` middleware extracts `Claims` into request context (`FromContext`). Gate 2 (action authorization) is a stub that auto-approves; the real CEL-based engine lands in `action/` at Phase C. Roles live in the IdP and travel in JWTs — reckon never caches or mirrors them. The `authz/action.go` stub is deliberately call-site-stable so inserting the real engine later only changes the constructor and decision shape.

**Server (`server/`).** `Backend` is the in-process HTTP server and itself a `supervisor.Component`. Dependencies arrive as connection strings (Pg DSN, Temporal host:port, Keycloak issuer URL) plus an injected `*aggregate.Handler` — it depends on *reachable services*, not on the components that brought them up, so it can be repointed at managed deps without touching the supervisor seam. `Start` runs a dependency probe (e.g. fetches Keycloak's OIDC discovery and asserts the issuer) before accepting traffic.

**Temporal worker (`temporal/`).** The in-process worker (`worker.go`) is a `supervisor.Component` that polls the `reckon` task queue — no separate worker binary (`05 §3.3`); it runs in the backend's process. A.7 registered the workflow inventory under stable type names; the remaining skeletons (`ReversalSaga`, `RenormalizePass`, `ArchiveInvestigation`, `PostConclusionPipeline`, `SummarizeForKnowledgeIndex`) still fail fast with `Unimplemented`. **Phase C.4** filled `ActionLifecycle` (`action_lifecycle.go` + `activities.go`) — the durable dispatch of an APPROVED action, the highest-correctness-stakes path (R15). It calls activities (which hold the aggregate handler + action resolver): the **dispatch-ledger guard** (`08 §6b` — `CheckDispatched` short-circuits if an `action.dispatched` already exists, so a replay/retrigger never double-executes), records `action.dispatched` **before** the outbound call (`adapter_request_id` = workflow id), dispatches under the retry budget (`04 §6.1`: 3 attempts, 2s/8s/30s; `FATAL_ERROR` non-retryable), and records `action.resulted` — with the honest residual on failure (`08 §6c`: FAILED + per-target UNKNOWN, never a success inference). The dispatch/result events are SYSTEM-only aggregate commands (`command.go` guard). `runtime.buildActionActivities` injects the activities when write bindings are configured. The **`request_action` HTTP endpoint** (`server/actions.go`, `POST /api/actions`, analyst role) ties it together: build x-action → Gate 2 → record request + `policy_evaluated` in one tx → on `AUTO_POLICY`, approve (attributed to the policy's accountable human) and `StartActionLifecycle` via the dispatch `Client`; else leave `PENDING_MANUAL`/`PENDING_TWO_PARTY`. `Actor.Kind` is derived from the JWT `delegate_kind` claim, never the body — closing the seam obligation so the baseline DENY (AI-no-T3) can't be spoofed. **`ReversalSaga`** (`reversal_saga.go`, `04 §7`) completes the write-side workflows: a reversal is a full x-action of the descriptor's `reversible_by` inverse type (same tier as the original), and the saga runs its `ActionLifecycle` as a child workflow, then — only if it actually took effect (SUCCEEDED/PARTIAL) — emits `action.reversed` on the original via the SYSTEM-only `ReverseAction` command (original must be SUCCEEDED). A failed reversal leaves the original SUCCEEDED (honest-state: never claim an undo that didn't happen). The endpoint routes a request with `reversal_of_ref` to `StartReversalSaga` instead of `StartActionLifecycle`. Phase C's write path (request → Gate 2 → approve → dispatch → result → reverse) is complete for v0. Note the package name clashes with the SDK's `go.temporal.io/sdk/temporal`, aliased as `sdktemporal`.

**Observability (`telemetry/`).** Phase A.8: `telemetry.Setup` installs the global `slog` logger (level/format-configurable, with rolling file logs under `<data>/logs`) and the global OpenTelemetry tracer provider — configured with **no exporter** at v0 (spans are created and nested in-process but not shipped; an OTLP exporter slots in at v1 without touching call sites). It also builds a private Prometheus registry served at `/metrics`. The returned `Provider` injects an `HTTPMiddleware` (root server span + request metrics) and the metrics handler into the `server.Backend` by function/handler — server stays decoupled from `telemetry`. Spans nest HTTP → `aggregate.Handle` → `aggregate.project` in one trace; the aggregate emits its spans via the cached global tracer (`otel.Tracer`), which safely delegates to whatever provider `Setup` installs (inert but harmless in unit tests that never call `Setup`).

**Identity (`identity/`).** Phase B.1: the deterministic tenant-scoped UUIDv5 resolver (`03 §7`). Pure, stateless — holds only the tenant namespace UUID, computes `<type>--<uuidv5>` over canonical JSON of each type's identity-contributing fields. Implements the three deliberate STIX deviations (process on `(host, pid, created_time@1s)` with anonymous-random fallback; email-addr and user-account lowercased; `account_type` never folded). Two hard rules: adapters never compute STIX ids (the normalizer, via this resolver, is the single arbiter), and the resolver only *folds* (case/whitespace/format) — per-type *shaping* of inputs (`domain\user` composition, host-identifier tier, hash selection) is the calling normalizer's contract (`03 §7.4`).

**Capability (`capability/`).** Phase B.2/B.4/B.5 so far: the transport-neutral `Adapter` interface (`03 §5.3`) with five classes and the `§6.2` error taxonomy (`RETRY`/`FALLTHROUGH`/`UNHEALTHY`/`FATAL` as `*AdapterError`, branched on by the future resolver); the telemetry-layer types (`OcsfPayload` → immutable `OcsfEvent` at ingest); the `FixtureAdapter` replaying `fixtures/<scenario>/*.json` (`03 §9`); and the normalizer layer (`03 §4`) — the interpretation-layer types (`SCO`/`ObservedData`/`Relationship`/`Edge`/`Provenance`), a class-keyed `Registry` with an opaque default (`§4.13`), and the `process_activity`/`authentication` normalizers, all minting identity through the resolver via a shared `resultBuilder`. and the verb resolver (`03 §3`) — declarative verb→binding→adapter selection by priority, the sealed parameter-templating engine (`§3.3`: `${path}`/`?`/`?? default`/`| transforms`, validated at config-load), and the five-value `Coverage` classification (`§6.1`). `Resolver.Resolve` walks bindings, templates+invokes the applicable/healthy one(s), normalizes the OCSF output, and returns the `CapabilityResult` envelope. Invariants: pure I/O, no reasoning, never authors `x-interpretation`, `derivation_mode = DIRECT` (sole exception: the detection_finding normalizer, `03 §4.12`, still to land). The `CapabilityDescriptor` catalog + `list_capabilities` (`§2.8`, `§6.3`) classify each verb as available/degraded/unavailable from its bindings' health. Runtime wiring is live: `capability.LoadTenantConfig` + `BuildResolver` construct the resolver/catalog from a tenant capability YAML (`config.Capability.ConfigPath`), and `runtime.buildCapability` threads them into the backend, which serves `GET /api/capabilities`. The layer is optional in v0 — no config path leaves the route a clean 503. Normalizers cover all v0 OCSF classes (`§4.1`–`§4.12`): process/auth/network/dns/file, the persistence classes (registry-key/scheduled-job/module), account-change, email/email-url, and the `detection_finding` INFERRED exception (Indicator + Sighting + vendor Identity, evidence recursed through the registry). The first fixture scenario ships as data: `fixtures/lateral-movement-via-rdp/` (OCSF events, `§9`) + `examples/capability/lateral-movement.yaml` (the tenant config binding four verbs to it), covered by a scenario smoke test. Phase B is complete for v0; the JSON-RPC/stdio transport for out-of-process adapters (`§5.4`) and real vendor adapters land in Phase E.

**Action / write side (`action/`).** Phase C.2: the symmetric twin of capability's read surface (`08`). `ActionDescriptor` catalog + `list_action_types` (available/degraded/unavailable), the `ActionBinding` model, and the **no-fall-through** action resolver — unlike the read resolver, once a binding is chosen a failed dispatch never retries against another tool (a partial state change must not be re-attempted). The `WriteAdapter` contract is `Dispatch(op, params, idempotency_key) → WriteResult` (an outcome, not an observation — no normalizer on the write path), with the layered idempotency key `f(x-action.id, target)`. `BuildRequestCommand` validates a `request_action` against the catalog and applies the **blast-radius escalator** (`04 §1`: a T2 action over the threshold distinct targets → T3, non-negotiable) before emitting C.1's `aggregate.RequestAction`. The `FixtureWriteAdapter` ("fake Tines") replays declared `WriteResult`s from `fixtures/<scenario>/*.action.json`. It reuses capability's templating via the exported `capability.RenderParams`/`ValidateParamTemplates`/`LookupPath`. **Phase C.3 — Gate 2** (`gate2.go`/`policy.go`): the CEL auto-approval engine (`04 §4`) that replaces `authz.PermissiveGate2`. `Gate2.Evaluate` runs versioned CEL policies over a flattened `EvalInput`→`ctx.*` projection and resolves an authorization `Decision` by priority (DENY > REQUIRE_TWO_PARTY > AUTO_APPROVE > manual); the non-deletable **baseline DENY** (`AI-no-T3`) is always prepended, so an AI-delegated T3 can never auto-approve regardless of tenant policy. Shadow policies (`04 §4.4`) are evaluated + recorded (`would_have_fired`) but never drive the decision. `ApplyDecision` threads the evaluation onto the `RequestAction` command so the `action.policy_evaluated` audit event (`02 §3`) is written in the same transaction as `action.requested`. Uses `cel-go`; `any_in`/`all_in` are v0 list-membership helpers. The `request_action` HTTP endpoint + the ActionLifecycle/ReversalSaga workflow bodies land with C.4 — the endpoint must derive `Actor.Kind` from the JWT `delegate_kind` claim.

**Migrations** live next to their owning package as embedded `fs.FS` (`aggregate/migrations/`, `knowledge/migrations/`) and are handed to the supervisor's Postgres component per-database (`reckon_main`, `reckon_knowledge`). Config schema is `config/config.go` (YAML; both binaries read the same schema).

`implementation/reckon-patterns.md` is the canonical short list of these patterns (pure-function + tx-wrapper, `Component` contract, two-axis auth chain, DI-by-connection-string, embedded-fs migrations, per-package `TestMain` with shared Pg). Read it once before writing new code in these packages.
