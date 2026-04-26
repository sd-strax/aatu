# Investigation Persistence Strategy — Spec

## Project context

"Cursor for SOC analysts" — AI-native investigation environment. Substrate: VS Code extension (primary), CLI (secondary), Java backend, Next.js frontend, transport-neutral capability layer for tool federation (adapters: MCP, native vendor APIs, custom integrations; see capability.md §5.4). Personas v0: threat hunters and IR responders. Workflows v0: investigation (entity-rooted) and hunting (hypothesis-rooted). v0 prototype runs against OCSF fixtures via the fixture adapter, not real tenants.

This spec defines how investigation state is persisted. It assumes the investigation domain model spec as authoritative input.

## Thread scope

- How investigation state is persisted (storage model, schema posture, evolution)
- How AI tool calls and reasoning traces are persisted and linked
- How human + AI authorship is recorded on every persisted action

## Out of scope

- The domain model itself (separate thread, taken as given)
- Action authorization mechanics (referenced where it touches event shape; full design separate)
- Capability layer (covered by capability.md)
- Query model and API surface beyond what projections require
- UI projections beyond their backing data shape

---

## 1. Decision summary

| Layer | Strategy | Reasoning |
|---|---|---|
| Investigation aggregate | Event-sourced | Replay, defensibility, AI reasoning audit, multi-analyst handoff, detection authoring all bite here and only here |
| x-action lifecycle | Event-sourced (inside the investigation aggregate) | Has a real state machine (REQUESTED → APPROVED → EXECUTING → terminal); same-aggregate placement makes the action ↔ producing-Interpretation write atomic and removes any cross-aggregate consistency story |
| STIX object layer (entities, ObservedData, Sightings, Indicators, Reports, Notes, Opinions, Relationships) | CRUD + thin change-history table | No state-machine invariants; mostly accretive; ES gives no leverage |
| OCSF telemetry | Append-only insert | Already immutable by construction; not an aggregate |
| AI tool calls | Append-only side store, content-hashed | Inherently event-shaped; not an aggregate; needs integrity guarantees |
| AI prompt/response transcripts | Append-only side store, content-hashed, retention-bounded | Bytes are cheap when stored where they belong; referenced not embedded |
| Users, tenants, adapter config, RBAC | CRUD | Boring on purpose |

## 2. Persistence model

**All persistence is per-tenant.** Every layer below — the investigation aggregate event stream, STIX object store, OCSF telemetry, AI tool-call and transcript side stores — is logically partitioned by tenant. v0 ships as a single Postgres instance with `tenant_id` on every row; physical sharding (separate databases per tenant, or table partitioning) is an operational concern deferred until tenant volume warrants it. Identity computation uses a per-tenant namespace UUID assigned at tenant creation (see domain_model.md ARCHITECTURAL COMMITMENTS and capability.md §7.1), so cross-tenant id collision is impossible by construction — the partitioning is correct-by-default rather than enforced solely by row-level filters.

### 2.1 Investigation aggregate (event-sourced)

The Investigation aggregate is the unit of event sourcing. Boundary: one Grouping plus its four extensions (Seed, Lifecycle, ReasoningThread, ConclusionSlot), its membership, its Interpretations, and its x-actions (the REQUESTED → APPROVED → EXECUTING → terminal lifecycle for any state-changing action taken from this investigation; see auth.md §3 for the action model and §3.2 for the lifecycle).

Things outside the boundary that the aggregate references but does not own: STIX entities, ObservedData, Sightings, OCSF events, AI tool calls, transcripts. The aggregate references them by id; their existence and lifecycle are managed elsewhere.

Aggregate state is reconstructed by folding the event stream in `sequence_no` order. Commands are validated against the folded state, then produce new events. Event append and projection update happen in a single transaction (see §4).

### 2.2 STIX object layer (CRUD + change history)

Each STIX object type has a current-state row and a thin `<type>_history` table. Change history captures who/when/what-changed for any mutation. STIX objects are mostly created and rarely mutated; the history table is small in practice.

This is *not* event sourcing. There is no fold to derive current state — current state is the row. The history table exists for audit, not for replay.

### 2.3 OCSF telemetry (append-only insert)

OcsfEvent rows are inserted on ingestion and never modified. No projections, no aggregates. Indexed for retrieval by entity reference, time, source tool, and class.

### 2.4 AI tool calls and transcripts (append-only side stores)

See §6 for the layered approach (structured-in-event, transcripts-by-reference, exhaust-dropped).

---

## 3. Event taxonomy

All events share a common envelope:

```
EventEnvelope
  event_id          UUID v7 (time-ordered; primary key)
  aggregate_id      grouping--<uuid>
  aggregate_type    "Investigation"
  sequence_no       monotonic per aggregate, starts at 1
  event_type        string
  event_version     int, starts at 1
  occurred_at       timestamp (business time)
  recorded_at       timestamp (write time)
  actor             { principal, delegate?, kind }    -- see §7
  causation_id      UUID, the command/event that caused this
  correlation_id    UUID, ties one logical operation (e.g. an LLM turn)
  tenant_id         UUID
  payload           JSONB, type-specific
```

### v0 event types

Lifecycle (each event is recorded in the same aggregate transaction as its corresponding `InterpretationRecorded` of type "lifecycle"; shared `correlation_id` ties them):
- `InvestigationCreated` — payload: seed (one of AlertSeed | EntitySeed | QuestionSeed), name, description, context ("investigation" | "hunt")
- `InvestigationStatusChanged` — payload: from, to, reason, lifecycle_interpretation_ref
- `InvestigationConcluded` — payload: report_ref, summary. The Report itself is created in the STIX object store (CRUD layer) **in the same Postgres transaction** as this event; the Report row write, the event append, and the lifecycle Interpretation all succeed or abort together. Eliminates the dual-write failure mode that would otherwise leave a CONCLUDED investigation pointing at a non-existent Report.
- `InvestigationReopened` — payload: reason. Clears conclusion_ref. Prior Report stays referenced from the thread.
- `InvestigationArchived` — terminal. After this event the aggregate accepts no further events of any kind.

Membership (Grouping.object_refs):
- `MemberAdded` — payload: stix_object_ref, rationale. **Only for external references** — bringing a STIX object that already exists in the store (an entity from another investigation, an ObservedData from a shared cache) into this investigation's scope. Nodes the aggregate creates internally (Interpretations, x-actions) are members implicitly via their creation event; no separate MemberAdded fires for them.
- `MemberRemoved` — payload: stix_object_ref, reason. Soft removal — historical membership is preserved by the event itself.

Reasoning thread:
- `InterpretationRecorded` — payload structure detailed in §6
- `InterpretationSuperseded` — payload: superseded_id, superseding_id, reason. No deletion; the thread shows both.

Evidence linkage:
- `EvidenceAttached` — payload: evidence_ref (`EvidenceRef` per domain_model.md INTERPRETATION → Reference types — `StixId | OcsfEventId`), interpretation_ref, role ("supports" | "refutes" | "context"), weight (STRONG | MODERATE | WEAK; required when role is "supports" or "refutes"; null when role is "context"). Role and weight match the `x-supports` / `x-refutes` edge vocabulary in domain_model.md EDGE TYPES.
- `EvidenceDetached` — payload: evidence_ref, reason

Action lifecycle (see auth.md §3 for the action model and §3.2 for the state machine):
- `ActionRequested` — payload: action_id, action_type, tier, targets, parameters, evidence_refs, expires_at, requesting_interpretation_id. Recorded in the same aggregate transaction as the producing `InterpretationRecorded` (interpretation_type "action-request"); shared `correlation_id` ties them. Permitted against a CONCLUDED investigation only when the request is a reversal action (see auth.md §9.1 and the domain_model.md Lifecycle invariants).
- `ActionApproved` — payload: action_id, authorization { mode (MANUAL | AUTO_POLICY | TWO_PARTY), stage (SOLO | PRIMARY | SECONDARY — SOLO for MANUAL/AUTO_POLICY; PRIMARY then SECONDARY for TWO_PARTY), primary_approver_ref, primary_approved_at, secondary_approver_ref?, secondary_approved_at?, policy_ref?, policy_version?, challenge_response? }, approval_interpretation_id. Resulting x-action status: PENDING_SECONDARY when (mode=TWO_PARTY, stage=PRIMARY); APPROVED otherwise. Subsequent rejection or expiry from PENDING_SECONDARY uses the existing `ActionRejected` / `ActionExpired` events.
- `ActionRejected` — payload: action_id, reason, rejection_interpretation_id.
- `ActionExpired` — payload: action_id, expiry_interpretation_id. System-emitted on `expires_at`.
- `ActionDispatched` — payload: action_id, adapter, adapter_request_id, dispatched_at, dispatch_interpretation_id. System-emitted when the dispatcher picks up an APPROVED action.
- `ActionResulted` — payload: action_id, final_outcome (SUCCEEDED | FAILED | PARTIAL | TIMEOUT), per_target_results, attempts, raw_response_ref?, result_interpretation_id. System-emitted; `per_target_results` is what makes PARTIAL outcomes auditable.
- `ActionReversed` — payload: original_action_id, reversing_action_id, reversal_interpretation_id. The reversing action is itself a new x-action (with its own `ActionRequested` etc.); this event records that the original's status moves to REVERSED on the reversing action's success.

Total: ~18 event types at v0. Named after analyst verbs. No derived-fact events. No fork events (deferred to v1+ — taxonomy stays clean enough that forking can be added without schema migration).

### Why these and not others

- No event for "EntityPromotedFromObservation" or "HypothesisContradicted" — both derivable from `InterpretationRecorded`. Don't make derived facts first-class.
- No event for STIX object creation. Entities, Sightings, etc. are created in the STIX object store independently. The investigation references them via `MemberAdded` / `EvidenceAttached`. This keeps entities reusable across investigations without forcing replay of every investigation that ever touched them. (x-actions are an exception — they are aggregate-internal and created by `ActionRequested` events, not in the external store.)
- No separate `MemberAdded` event for aggregate-internal nodes (Interpretations, x-actions). Membership is implicit at creation time; a separate event would be bookkeeping that doubles event volume during action lifecycles for no information gain.
- No `InvestigationForked` event at v0. Forking-as-branching has not shown enough demand. Replay-as-reading (walking the event stream in order) is a v0 feature; replay-as-re-execution and forking are v1+.

---

## 4. Storage choice

**Postgres, single events table, no event-sourcing framework.**

### Rationale

The decisive property: atomic event append + projection update in one transaction. This kills the eventual-consistency cost listed in the original tension. With Axon or EventStoreDB you have two systems and a dual-write failure mode. With Postgres, append-and-project is a single transaction.

Other reasons:
- One operational surface (Postgres already holds STIX objects, OCSF, projections, CRUD tables).
- JSONB plus GIN indexes is sufficient for heterogeneous event payloads at v0 scale.
- Team familiarity. No new ops surface, no new client library to learn.
- Axon Framework brings an opinionated CQRS/saga model and runtime; the sugar isn't worth the lock-in at v0 scale.
- EventStoreDB is the right answer at 100x v0 scale, when catch-up subscriptions across services matter. Today, it's a second database with its own backup story.

### Events table

```sql
CREATE TABLE investigation_events (
  event_id          UUID PRIMARY KEY,
  aggregate_id      TEXT NOT NULL,
  aggregate_type    TEXT NOT NULL,
  sequence_no       BIGINT NOT NULL,
  event_type        TEXT NOT NULL,
  event_version     INT  NOT NULL,
  occurred_at       TIMESTAMPTZ NOT NULL,
  recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor             JSONB NOT NULL,
  causation_id      UUID,
  correlation_id    UUID,
  tenant_id         UUID NOT NULL,
  payload           JSONB NOT NULL,

  UNIQUE (aggregate_id, sequence_no)
);
```

The `(aggregate_id, sequence_no)` unique constraint provides optimistic concurrency: append uses `INSERT ... VALUES (?, ?, expected_next_seq, ...)` and on unique violation the writer reloads, re-validates, retries.

Indexes (illustrative, tune from observed query patterns):
- `(aggregate_id, sequence_no)` — primary load path for fold
- `(tenant_id, recorded_at DESC)` — cross-tenant audit and recent-activity
- `(event_type)` — analytics and detection authoring
- `(correlation_id) WHERE correlation_id IS NOT NULL` — reconstruct one LLM turn

### Snapshots

Not at v0. Investigations are bounded in event count (estimated 20–100 events per investigation; long-running IR cases the high end). Fold time at this scale is sub-millisecond. Introduce snapshots when median fold latency crosses a threshold determined empirically (~50ms is a reasonable trigger), not on a calendar.

### Projections

Two read models at v0. Both updated in the same transaction as the event append.

`investigation_current` — one row per investigation, denormalized for the workspace view (status, seed, conclusion_ref, member_refs summary, last_sequence_no for optimistic concurrency, etc.). Read by the VS Code extension's open-tab view. Hot path.

`investigation_thread` — one row per Interpretation, in stream order, with denormalized references. Read by the reasoning-thread UI and by replay / detection-authoring tools. Walked in order.

Add projections incrementally as new read patterns emerge. Don't pre-build read models for hypothetical queries.

---

## 5. Schema evolution

Stance: **version events; allow controlled rewrites within a defined freeze window; never rewrite past the window.**

Concrete rules:

- Every event carries `event_version`, starting at 1.
- For non-breaking changes (new optional field, additional metadata), bump version, write upcasters that read old versions into the new shape on fold. History stays untouched.
- For breaking changes within the **freeze window** (defined per-event-type; default proposal: 90 days from first production write of that event type), in-place rewrite is permitted with an explicit migration record. The migration record itself is a row in a `schema_migrations` table noting what was rewritten, when, by whom, and why.
- After the freeze window closes for an event type, that type is frozen. Breaking changes require new event types and upcasters.
- v0-era events are explicitly tagged "v0, expect breaking changes pre-GA" so the freeze policy doesn't paint the team into a corner before the model has stabilized.

Rationale: pure "never rewrite" is correct in principle and miserable in practice during the period when the model is still being shaped. The freeze window codifies the discipline that pragmatism is bounded — you get a window to fix shape mistakes, then you live with what you wrote.

---

## 6. AI reasoning in the persistence model

The reasoning persistence problem decomposes into three layers. The split is the answer to "how do we capture AI reasoning without exploding the event store with natural-language exhaust."

### Layer A — Persisted in the event, structured

The Interpretation event payload contains:
- `interpretation_id`
- `interpretation_type` — string drawn from the canonical enum (see domain_model.md INTERPRETATION → Interpretation types; 18 values at v0)
- `input_refs` — STIX or OCSF ids the reasoning departed from (matches `INTERPRETATION.input_refs` in the domain model)
- `output_refs` — STIX ids the reasoning produced (matches `INTERPRETATION.output_refs` in the domain model)
- `rationale` — bounded natural-language string (proposed cap ~500 chars). The "why," terse by design.
- `confidence` — HIGH | MEDIUM | LOW (optional)
- `tool_call_refs` — list of `{call_id, content_hash}` references into the tool-call store
- `transcript_ref` — `{transcript_id, turn_id, content_hash}` if AI-authored; null if human-authored

This is small per-Interpretation, structured, and high-value. Defensibility queries against `from_refs` / `to_refs` / structured tool-call references are fast and don't require parsing prose.

### Layer B — Persisted in side stores, referenced from the event

Two side stores, both append-only and content-hashed:

**`ai_tool_calls`** — full tool call arguments and full tool results. Bytes that are inherently structured (per-tool JSON schemas), but voluminous. Referenced from Interpretation events by `{call_id, content_hash}`. Hash on the event verifies the referent; if the stored call is altered, the hash mismatch surfaces.

**`ai_transcripts`** — full prompt and full model response for each LLM turn. Natural-language bytes. Referenced from Interpretation events by `{transcript_id, turn_id, content_hash}`.

Properties:
- Immutable. Once written, never modified.
- Complete. Verbatim prompts, verbatim responses, verbatim tool I/O. Not summaries, not previews.
- Tamper-evident. Content hash recorded on the Interpretation event at write time.
- Retention-bounded. Retention is a **config value**, set per tenant, governed by the tenant's regulatory and operational requirements. The reference-and-hash pattern is unaffected by retention — when a transcript ages out, the hash on the Interpretation still proves whether any later-presented bytes were the original.

Rationale for keeping these out of the event log: NL bytes are voluminous and live cheaply in object storage or a side table designed for them. The event log stays small, hot, and queryable. The structured Interpretation tells the story; the transcript is available on demand for the audit case.

### Layer C — Not persisted

Dropped at the source:
- Token-level streaming chunks
- Intermediate model thinking that did not influence a tool call or final answer
- Retry attempts the system discarded
- Embeddings, retrieval scores, reranking metadata

If any of this is needed for product development, it goes to the observability stack (separate concern), not the persistence layer.

### Implication for projections

The reasoning-thread UI walks Interpretations and renders Layer A inline. "Show full AI reasoning" is a click that fetches Layer B by reference. This matches how analysts actually work: the conclusion and structured evidence in front of them, the full transcript a click away when they want to dig.

---

## 7. Authorship: human principal, optional AI delegate

Every event records a human principal. AI involvement is captured as a delegate, never as a standalone principal.

```
actor
  principal       { user_id, display_name }       -- always a human
  delegate?       { agent_id, agent_kind, model } -- optional; the AI agent if any
  kind            HUMAN | AI_DELEGATED            -- derived: HUMAN if delegate is null
```

### Why this shape

- **Defensibility.** "Analyst Sarah is responsible for this conclusion, executed via Claude on date X" is the right frame for regulators and counsel. A pure AI principal would muddy responsibility; delegate cleanly preserves the chain.
- **Audit queries.** "Everything Sarah did" returns both her direct and AI-delegated actions. "Everything done via AI" filters on `delegate IS NOT NULL`. Both are useful.
- **Operational.** Authorization can derive from the principal's permissions while still recording the delegate that performed the action.

### Authorization (referenced; full design separate)

Authorization is the **intersection** of principal permissions and delegate policy. A delegated action is permitted iff:
1. the principal has the permission, AND
2. delegate policy permits AI delegates to perform this action class, AND
3. per-action delegate constraints are satisfied (rate limits, requires-confirmation flags, blast-radius caps).

Delegates may be restricted further than their principal but never broader. The principal's permissions are the ceiling.

This is a *write-time check*, not a stored property. The event captures what was permitted and executed; it does not capture the policy that permitted it. (If regulatory requirements ever demand policy-at-time-of-decision in the audit trail, add a `policy_snapshot_ref` field to the envelope. Deferred to v1 absent a driver.)

---

## 8. What's deferred to v1+

- **Forking-as-branching.** Designed-out at v0; taxonomy stays clean enough to add without breaking changes.
- **Replay-as-re-execution.** Replay-as-reading works at v0 (walk the event stream, render the thread). Re-running an investigation against new data or a different model is v1+ and will require additional design — particularly around determinism of AI calls and how forked-and-replayed investigations relate to their source.
- **Snapshots.** Add when fold latency demands; not before.
- **Cross-investigation linkage events.** Tag, "see-also," and similar relations between investigations. Add when product demand surfaces; do not pre-design.
- **Policy snapshots on events.** Add only if regulatory drivers require policy-at-time-of-decision in the audit trail.
- **Catch-up subscriptions across services.** Postgres LISTEN/NOTIFY or polling suffices at v0 scale. Revisit when service count grows.
- **Detection authoring as a feature.** The investigation event stream and the reasoning-thread projection are designed to support a future detection-authoring tool — analyst marks parts of an investigation as the basis for a detection rule, the tool generates rule code, and the rule is pushed through the auth.md push-to-production flow (T3, see §2 Action Categorization). The authoring tool itself is not specified in any v0 thread; the data model accommodates it without further change. References to "detection authoring" in §1 (decision summary), §3 (event indexing), and §4.2 (projection consumers) are about supporting this future use case, not committing to build it in v0.

---

## 9. Open items for the team

These are decisions or operational details intentionally left to the team rather than fixed in this spec:

- Concrete value of the schema-evolution **freeze window** per event type (proposed default: 90 days; team to confirm).
- Default tenant transcript retention (operational/legal call, not a design call).
- Choice of object store vs. Postgres side table for `ai_transcripts` (operational call; either works with the reference-and-hash pattern).
- Initial set of OCSF classes ingested at v0 (depends on the capability layer; see capability.md §4 — not this spec's concern).
