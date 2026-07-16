# Write-Side Adapter Contract — Spec

## 0. Framing

This spec defines the **write-side adapter contract**: the I/O surface by which an authorized
`x-action` is dispatched to the outside world and its result is recorded. It is the symmetric twin of
the read-side capability contract in `03-capability-layer.md`. Where `03` covers query verbs (binding
→ resolver → adapter → normalizer → `CapabilityResult`), this spec covers action types (binding →
resolver → adapter → `WriteResult`). The architecture is deliberately the same shape; the differences
— idempotency, no normalizer, asynchronous SOAR callbacks — are called out where they occur and
justified.

The action **domain model is already specified elsewhere and is authoritative**; this spec does not
restate it. It owns only the adapter-facing contract.

| Owned here (`08`) | Owned elsewhere (authoritative) |
|---|---|
| The `request_action` tool schema | Authorization, trust tiers, CEL policy (`04`) |
| `ActionDescriptor`, action bindings, the action resolver | The `x-action` primitive, lifecycle, `Execution` record (`01`, `04 §3`, `04 §6.1`) |
| The write adapter operation signature + idempotency model | Action lifecycle events + payloads (`02 §3`) |
| The `WriteResult` envelope | Temporal dispatch topology, manifest/registry (`05 §6.2`, `05 §11`) |
| Action fixtures | The action-type taxonomy (`04 §2`, `07 §7`, `07 §8`) |

### Out of scope

- **Authorization.** Whether an action *may* dispatch is settled by the time this contract engages.
  This spec begins at the `APPROVED → EXECUTING` transition.
- **The action-type catalogue.** Tiers, reversibility, and D3FEND mappings live in `04 §2`/`§2.1`
  and `07`. This spec defines the *carrier* (`ActionDescriptor`), not the catalogue.
- **Vendor-specific adapter internals.** As on the read side, transport is an adapter concern.
- **Credential resolution.** Adapters receive a `credentials_ref`; resolution is the uniform scheme
  in `05 §10.2`.

---

## 1. The shape of the write path

Symmetric to the read pipeline (`03 §3`), with the resolver embedded in the `ActionLifecycle`
Temporal workflow (`05 §6.2`) rather than a synchronous request:

```
request_action (LLM/analyst)            <- §2
  -> x-action REQUESTED                 (04 §3.2; authorization in 04)
  -> ... APPROVED ...                   (04 §5)
  -> ActionLifecycle workflow           (05 §6.2)
       resolve action binding           <- §4
       build idempotency key            <- §6
       dispatch-ledger guard            <- §6
       adapter.dispatch(op, params, idempotency_key) -> WriteResult   <- §5, §5-envelope
       classify outcome                 <- §5
       emit ActionDispatched / ActionResulted (02 §3)
```

The principle from `05` commitment #5 holds: adding a remediation tool is "register an adapter, add
bindings, declare an action descriptor." No structural change.

---

## 2. The `request_action` tool

`request_action` is the single agent-facing tool that proposes a state-changing action. Its canonical
schema lives here (it is a capability-surface object, symmetric to the read verbs in `03 §5.3`);
`04 §5.6` references it and owns only what happens to the request inside the authorization machine.

```
request_action(
  action_type        string            -- from the ActionDescriptor catalogue (§3)
  targets            list<TargetSpec>  -- the things acted on (04 §3.1, §8.1)
  parameters         object            -- action-type-specific inputs (validated vs §3 input schema)
  evidence_refs      list<EvidenceRef> -- STIX ids / OcsfEvent ids justifying the action (01)
  rationale          string            -- why this action should happen
  investigation_ref  grouping--<uuid>  -- the owning investigation aggregate
)
```

**The AI/analyst boundary.** The AI may *call* `request_action`, but it can never construct an
`Authorization` record or set `status` — those fields are write-protected at the aggregate command
handler (`04 §5.6`, enforced per `02-persistence.md §2.1`/`§4`). Calling the tool produces an `x-action` in
`REQUESTED` and its producing `action-request` Interpretation, in one transaction. Everything between
`REQUESTED` and `APPROVED` is `04`'s; this contract resumes at dispatch.

`TargetSpec` (defined in `04 §3.1`) carries both `entity_ref` (stable STIX id) and
`resolved_identifier` (what the adapter actually sends downstream). Resolution is frozen into the
`x-action` at request time (`04 §8.1`); the write adapter consumes `resolved_identifier`, never
re-resolves.

---

## 3. `ActionDescriptor`

The write analog of `CapabilityDescriptor` (`03 §5.3`). It declares the action surface the LLM sees
and the bindings target.

```go
type ActionDescriptor interface {
    ActionType() string          // e.g. "host.isolate", "ticket.create"
    Inputs() InputSchema         // schema for request_action.parameters
    Intent() string              // LLM-facing description of effect + when to use
    // Auth/taxonomy fields below are DECLARED here but OWNED elsewhere:
    DefaultTier() Tier           // T1|T2|T3 — authoritative in 04 §2
    Reversibility() Reversal     // reversible / best_effort / irreversible — 04 §7 (the
                                 // classification gates the REVERSED claim, 04 §7.1)
    D3FEND() string              // optional technique id — 04 §2.1
}
```

`DefaultTier`, `Reversibility`, and `D3FEND` are surfaced on the descriptor (and in the adapter
manifest, `05 §11`) for discoverability, but `04`/`05` remain their single source of truth — `08`
must not diverge from `04 §2`'s categorization table. An action type appears in `list_action_types`
once its descriptor is registered and at least one binding exists (mirroring `03 §5.1`).

---

## 4. Action binding model

Symmetric to the read binding (`03 §3`). A binding maps an `action_type` to a concrete adapter
operation in tenant config:

```
ActionBinding:
  action_type   string          -- the descriptor this fulfills
  adapter       string          -- adapter name (e.g. "crowdstrike_falcon", "tines_playbook")
  operation     string          -- concrete write op on that adapter (e.g. "rtr.isolate_host")
  priority      int             -- highest applicable wins (as read side)
  params        object          -- templated parameter mapping (request params + target -> op inputs)
  external_approval_substitutes_reckon  bool  -- SOAR gate ownership (§7; default false)
```

**The action resolver** (the dispatch-step analog of the read resolver, `03 §3.2`): given
`(action_type, x-action, tenant)`, pick the highest-priority binding whose preconditions hold
(adapter enabled, credentials configured, target type applicable), render the parameter template
against the frozen `TargetSpec`s and `parameters`, and hand off to the adapter operation.

Unlike the read resolver, the action resolver does **not** fall through to a lower-priority binding on
a failed call — a partially-executed state change must not be silently re-attempted against a
different tool. Binding selection is resolved once, before the first outbound attempt; retries
(`§6`) re-use the same binding.

---

## 5. Write adapter operation contract

Write operations extend the same `Adapter` interface as the read side (`03 §5.3`); an adapter may
serve read operations, write operations, or both. The write operation differs from `Invoke` in two
ways: it takes a mandatory `idempotency_key`, and it returns a `WriteResult` rather than an
OCSF-shaped response (there is no normalizer on the write path — a write produces an *outcome*, not
an observation).

```go
type WriteAdapter interface {
    // ... Name(), Class(), Health() as in 03 §5.3 ...
    SupportedActionOps() []string
    Dispatch(ctx context.Context,
             operation string,
             params map[string]any,
             idempotencyKey string) (WriteResult, error)
}
```

Adapters remain out-of-process JSON-RPC binaries over stdio (the shape `generate-adapter-scaffold`
produces); a write op is one more JSON-RPC method whose params include `idempotency_key` and whose
result is the `WriteResult` envelope below.

### The `WriteResult` envelope

The write analog of `CapabilityResult` (`03 §2`). Its fields map field-for-field onto the `Execution`
record (`04 §6.1`) and the `ActionResulted` payload (`02 §3`) so the contract and the event log agree
by construction:

```
WriteResult {
  final_outcome      SUCCEEDED | FAILED | PARTIAL | TIMEOUT   -- = Execution.final_outcome
  per_target_results map<target_index, OK | FAIL | UNKNOWN>   -- = Execution.per_target_results
  adapter_request_id string         -- correlation id (see §6 / 05 §6.2)
  error_class        RETRYABLE_ERROR | FATAL_ERROR | null  -- matches 04 §6.1 Attempt.outcome; null on success
  error_detail       string?        -- human-readable
  audit_depth        FULL | EXTERNAL -- FULL for DIRECT, EXTERNAL for SOAR_PLAYBOOK (§7; 04 §6.1)
  raw_response_ref   ref?            -- optional pointer to the stored adapter response
}
```

**Error classification** reuses the read-side taxonomy (`03 §6.2`) collapsed to what the executor
acts on: `RETRYABLE_ERROR` (rate limit, transient 5xx, network blip → retry within the budget, `§6`) and
`FATAL_ERROR` (auth, malformed request, target-not-found → no retry, `FAILED`). This matches the
categories in `04 §6.1`/`§6.2`.

**`UNKNOWN` per-target** is a first-class result, not an error: it means the call left reckon but the
adapter cannot confirm the per-target effect. It never coerces to `OK` — see the idempotency residual
in `§6`.

### The optional `verify` operation (reversal verification, 04 §7.3)

An adapter MAY additionally implement a verification operation for reversals:

```go
    // Verify reports whether the effect of a previously-dispatched operation is
    // observably GONE from the tool's vantage point — the evidence that lets a
    // BEST_EFFORT reversal earn the REVERSED claim (04 §7.3). Same result
    // vocabulary as Dispatch: OK = verified gone, UNKNOWN = removed what this
    // tool governs but cannot confirm the rest (propagation, partner feeds),
    // FAIL = still in effect.
    Verify(ctx context.Context,
           operation string,
           params map[string]any) (WriteResult, error)
```

Semantics per `04 §7.3` (state ownership): for a `REVERSIBLE` action the tool owns the effect state,
so `Dispatch` success on the inverse *is* the verification and `Verify` is unnecessary. For a
`BEST_EFFORT` action, `Dispatch` success on the inverse only records an *attempt*
(`action.reversal_attempted`, `02 §3`); a `Verify` returning all-targets-`OK` upgrades the outcome to
the verified undo (`action.reversed`). An adapter that does not implement `Verify` simply never
upgrades — the conservative default. The claim is earned per-dispatch by evidence, never granted by
configuration. Interface specified at v0; concrete implementations land with the real vendor write
adapters (Phase F). The fixture write adapter may declare verification verdicts in fixture files to
exercise the path.

---

## 6. Idempotency model

State-changing actions dispatch inside the `ActionLifecycle` Temporal workflow (`adapter_request_id`
= the Temporal workflow id, `05 §6.2`). The hazard the read side never has: a workflow
replay/crash/retry must not double-execute a real-world effect (double-isolate a host, double-file a
ticket). The model is layered, and honest about the one case nobody can resolve.

**(a) Mandatory idempotency key.** Every write op receives a `idempotency_key` that is **stable and
deterministic** — derived from `f(x-action.id, target)` — so the same logical action against the same
target always presents the same key. Adapters declare `honors_idempotency: true|false` in their
manifest (`05 §11`); for `true` adapters the downstream vendor dedups on the key (the standard
`Idempotency-Key` pattern). The key is the second line of defence: it protects the case where reckon
*does* re-issue after an ambiguous failure.

**(b) reckon dispatch-ledger guard (primary).** Before any outbound call, the workflow checks whether
an `ActionDispatched` event already exists for this `(x-action, attempt)`. Because the `x-action`
lifecycle is event-sourced (`02 §3`) and Temporal execution is deterministic on replay, a crashed or
replayed workflow sees the prior `ActionDispatched` and **short-circuits re-issue** rather than
calling the adapter again. reckon owns this guarantee from its own event log — it does not depend on
the vendor honouring the key. (a) and (b) compose: the ledger prevents re-issue in the common
crash/replay case; the key catches the residual races (a) can't see.

**(c) The honest residual.** If the call left reckon but no result returned (network partition after
send, adapter died mid-call), the per-target result is `UNKNOWN` and the action terminates `FAILED`
with `confidence = LOW` and **no success inference** — the analyst re-requests. This is the same
non-inference rule `04 §6.2` already applies to `TIMEOUT`: reckon never pretends to know an effect it
cannot confirm. Pre-dispatch state reconciliation (a `probe(target)` op that lets the executor skip a
call when the target is already in the desired state) would shrink this residual but is **not**
required by this contract — it is noted as a possible per-adapter capability in `§9`.

---

## 7. Dispatch sequence and SOAR delegation

### 7.1 Direct (`DIRECT`) dispatch

Inside `ActionLifecycle` (`05 §6.2`), on `APPROVED`:

1. Resolve the action binding (`§4`).
2. Build the idempotency key (`§6a`); run the dispatch-ledger guard (`§6b`).
3. `Dispatch(op, params, idempotency_key)`; apply the retry budget — default **3 attempts, 2s/8s/30s
   backoff** (`04 §6.1`, `§6.3`); each attempt is an `Execution.attempts` row.
4. Classify the `WriteResult`; emit `ActionDispatched` then `ActionResulted` (`02 §3`) with workflow
   context as the principal carrier (`05 §6.2`).

**Partial success across targets** terminates `SUCCEEDED` with `final_outcome = PARTIAL`; failed
targets are **not** auto-re-dispatched — recovery requires a new `request_action`, so every action
stays independently auditable (`04 §6.2`).

### 7.2 SOAR-delegated (`SOAR_PLAYBOOK`) dispatch

When the binding sets `external_approval_substitutes_reckon: true` (`04 §5.7`), the action is handed
to an external orchestrator (Tines/Torq/customer-authored) that owns the approval gate and the
execution. The contract differences:

- `Authorization.mode = EXTERNAL_DELEGATED`; `primary_approver_ref` is populated from the SOAR's
  **async callback** once the orchestrator confirms approval (`04 §5.7`).
- `audit_depth = EXTERNAL` on the `WriteResult`/`Execution` — reckon records the call to the
  orchestrator, the playbook id, and the final outcome, but not the orchestrator's internal steps;
  reviewers needing the full chain pull the SOAR's own logs (`04 §6.1`).
- `adapter_request_id` correlates the reckon-side workflow to the orchestrator run id returned on the
  callback.

Idempotency for SOAR dispatch still applies at (a)/(b): the key travels to the orchestrator (which
may or may not honour it) and the ledger guard prevents reckon re-issuing the playbook trigger.

---

## 8. Extension mechanism

Symmetric to `03 §5`.

**Add a write action type (three artifacts):**
1. An `ActionDescriptor` (`§3`).
2. At least one `ActionBinding` mapping it to an adapter operation (`§4`).
3. The action type listed in the serving adapter's manifest `action_types` (`05 §11`).

**Add a write adapter (four artifacts):**
1. A `WriteAdapter` implementation exposing named write operations (`§5`).
2. Adapter config schema (YAML), including `honors_idempotency` (`§6`).
3. Manifest `action_types` declarations (`05 §11`).
4. Bindings for the action types it fulfils.

No normalizer step exists on the write side (a write yields an outcome, not an observation) — this is
the one artifact the read-side extension list (`03 §5.2`) has that this one drops.

---

## 9. Action fixtures

The write analog of `03 §9`. A **fixture write adapter** (`adapterClass = FIXTURE`) lets v0 dispatch
exercise the full lifecycle — request → authorize → dispatch → `ActionResulted` → reversal — without
touching a real tool. A fixture declares the outcome it returns:

```json
{
  "fixture_meta": {
    "scenario": "contain-lateral-movement",
    "matches": { "action_type": "host.isolate", "params": { "resolved_identifier": "WIN-A14" } },
    "delay_ms": 200
  },
  "result": {
    "final_outcome": "SUCCEEDED",
    "per_target_results": { "0": "OK" },
    "audit_depth": "FULL"
  }
}
```

Fixtures store **outcomes**, not vendor responses (mirroring the read side's "store OCSF, not raw
vendor JSON" rationale, `03 §9.1`): this keeps fixtures exercising the dispatch/lifecycle/audit
machinery rather than a specific adapter. Fixtures can declare `PARTIAL`, `FAILED`, `TIMEOUT`, and
`UNKNOWN` results to drive the failure-path and reversal tests. As on the read side, a tenant may mix
fixture and real write bindings per-binding (`03 §9.3`). A fixture write adapter that also exposes a
`probe` op can exercise the optional reconciliation path (`§6c`).

---

## 10. Open questions / deferred to v1+

- **Composite / atomic multi-effect actions.** Whether a single `x-action` may bundle multiple
  effects (atomic in the audit and authorization sense), or multi-step stays the agent loop's job
  with per-action gates. v0 defers to the agent loop (`05`, "guard against half-finished AI
  multi-step responses").
- **Pre-dispatch state reconciliation as a requirement.** `§6` makes `probe(target)` optional; a
  future revision may require it for reversible state-change action types if the `UNKNOWN` residual
  proves operationally costly.
- **Idempotency key derivation across retargeting.** The `f(x-action.id, target)` key is stable per
  target; the precise canonicalization (and whether `attempt_no` participates) is settled at
  implementation time alongside the dispatch ledger.
- **Credential-resolution specifics for write creds.** Deferred to the uniform scheme in `05 §10.2`;
  write creds live in vault and are resolved only inside the execute step (`05 §6.2`).

---

*End of spec. The read-side counterpart is `03-capability-layer.md`; the action domain model is
`04-action-authorization.md` (authorization), `02-persistence.md §3` (events), and
`05-component-architecture.md §6.2` (dispatch topology).*
