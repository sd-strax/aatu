# Action Authorization & Trust Tiers — Spec

## 0. Framing

State-changing actions in a SOC live on a knife edge: too much friction and the system is useless during incident response; too little and one bad inference takes production down. This spec defines how actions are proposed, authorized, executed, audited, and reversed — anchored to the investigation domain model so that every action is inseparable from the reasoning that justified it.

**Three load-bearing principles:**

1. **The AI proposes; a human (or a pre-declared policy speaking for humans) disposes.** The AI agent never directly executes anything beyond READ and ANNOTATE. Tier 3+ execution requires either an explicit human act or a pre-registered policy that a human authored.
2. **Every action is the output of an Interpretation.** Authorization is not a side-channel — it lives in the reasoning thread, with `input_refs` pointing at the evidence that justified the action.
3. **Blast radius, not action verb, drives the tier.** "Isolate one host" and "isolate 500 hosts" are not the same action even though they hit the same downstream tool.

---

## 1. Trust Tiers (revised)

The proposed four tiers are mostly right but conflate two orthogonal axes: **reversibility** and **blast radius**. A targeted irreversible action (delete one phishing email from one mailbox) is meaningfully different from a wide reversible one (isolate 200 hosts). The fix is to keep four tiers but make blast radius an explicit *escalator* between them rather than packing it into tier 4.

### Tier definitions

**T0 — READ.** Query telemetry, fetch entity details, run searches, read existing investigations. No friction. Default for the AI agent and for any human session. Logged at debug level only; not part of the reasoning thread unless the analyst explicitly captures the result.

**T1 — ANNOTATE.** Mutations confined to the interpretation layer of the system itself: create/edit hypotheses, add Sightings, tag entities, propose detections (as drafts, not deployed), write Notes, change investigation lifecycle (`DRAFT → ACTIVE → PAUSED`). No friction. Always recorded as Interpretations in the normal way. The AI agent operates freely here.

**T2 — REVERSIBLE EXTERNAL ACTION.** Side effects on the outside world that can be cleanly undone: host isolation, session revocation, file quarantine, account suspension (not deletion), single-message mailbox quarantine, process kill on a running session. Single-key confirm in the IDE/CLI with the proposed action and its cited evidence rendered. The AI agent may *request* but never execute.

**T3 — IRREVERSIBLE OR HIGH-BLAST-RADIUS ACTION.** Either (a) genuinely irreversible — delete email from mailboxes, force credential rotation org-wide, push detection rule to production, delete data, terminate accounts — or (b) any T2 action whose target set exceeds a configured blast-radius threshold. Requires explicit typed confirmation (re-type the action verb and target count), and may require second-analyst sign-off depending on policy. Always full audit trail with mandatory rationale.

**Escalation rule:** any T2 action targeting more than `policy.blast_radius.t2_to_t3_threshold` distinct entities is automatically promoted to T3. Default threshold: 10 entities, configurable per action class. This is non-negotiable in code — it's not a policy override the org can disable, only adjust.

The escalator promotes the *tier*, not the *authorization mode*. An analyst-authored auto-approval policy whose predicate matches an escalated T3 action will still auto-approve it. This is intentional: analysts who author such policies are accountable for the predicates' blast-radius implications, and the spec does not second-guess them. AI-originated auto-approvals on T3 are separately blocked at the policy layer by the baseline DENY in §4.3 (Example 2), which is non-removable.

### Why not collapse to three or split to five

Three (read / annotate / external) loses the reversibility distinction, which is exactly the distinction analysts care about under time pressure: "I can untoast this in 30 seconds if I'm wrong" vs "this is final." Five tiers (splitting reversible-targeted vs reversible-broad, etc.) duplicates what the blast-radius escalator handles. Four with an escalator gives you the cognitive simplicity of four cuts and the precision of five.

### Awkward cases and how they resolve

- **"Push detection rule to production"** — T3, always. Rules trigger future actions; pushing one is a delegation of authority into an automated path. Treating it as T2 because "you can just delete the rule" misses that the rule may have already fired between push and revert.
- **"Kick browser session"** — T2. User logs back in; reversible.
- **"Force password reset"** — T2 for one user, T3 for many (escalator). The user can complete the reset; nothing is destroyed.
- **"Delete email from mailboxes"** — T3. Even one mailbox: the email is gone. The "reversibility" of restoring from backup doesn't count — that's a recovery operation, not an undo.
- **"Block hash/IP/domain at perimeter"** — T2 if the block list has a TTL and a clean removal API; T3 if it's a permanent block list or one that propagates to partner orgs. Most EDR block-hash APIs are T2.
- **"Submit file to sandbox / VT"** — T1 if the org has confirmed sandbox is private and submission isn't a disclosure; T2 if submission is to a public/shared service (because it leaks a file out of the org).

---

## 2. Action Categorization

Default tiers for common SOC actions. Orgs can shift any action *up* a tier via policy but never *down* without an explicit signed configuration change (see §4).

| Action | Default tier | Notes |
|---|---|---|
| Query EDR telemetry, SIEM logs, identity logs | T0 | |
| Pivot on entity, fetch enrichment | T0 | |
| Read another investigation's content | T0 | RBAC still applies |
| Submit hash to internal sandbox | T1 | If private-only |
| Submit file/hash to VT or external sandbox | T2 | Information disclosure |
| Create/edit hypothesis, Sighting, Note | T1 | |
| Tag entity, label investigation | T1 | |
| Draft detection rule (not deployed) | T1 | |
| Change investigation lifecycle to ACTIVE/PAUSED | T1 | |
| Conclude investigation (CONCLUDED) | T1 | Requires `conclusion_ref` per domain model |
| Archive investigation | T1 | |
| Reopen concluded investigation | T1 | |
| Isolate host (single) | T2 | |
| Un-isolate host | T2 | Reversal of a T2 |
| Kill process on endpoint | T2 | |
| Quarantine file on endpoint | T2 | |
| Suspend user session / revoke tokens | T2 | |
| Suspend user account (re-enableable) | T2 | |
| Force MFA re-enrollment (single user) | T2 | |
| Force password reset (single user) | T2 | |
| Block hash/IP/domain at perimeter (with TTL) | T2 | |
| Quarantine single email from one mailbox | T2 | Restorable from quarantine |
| Push detection rule to production | T3 | Always |
| Delete email from mailboxes (purge) | T3 | |
| Disable user account (terminal, not suspend) | T3 | |
| Mass session revocation (>threshold users) | T3 | Escalator from T2 |
| Mass host isolation (>threshold hosts) | T3 | Escalator from T2 |
| Force password reset, multiple users | T3 | Escalator from T2 |
| Delete data from data store (any) | T3 | |
| Modify firewall/proxy policy at scope | T3 | |
| Reimage host | T3 | |
| Permanent block list addition (no TTL) | T3 | |
| Disable detection rule in production | T3 | Same blast radius as enabling one |
| Open ticket / incident in SoR (Jira, ServiceNow, Linear) | T1 | Operational handoff; no external blast radius beyond the SoR |
| Update existing ticket | T1 | |
| Post to chat channel (Slack, Teams) | T1 | Org-internal communication |
| Page on-call (PagerDuty, OpsGenie) | T2 | Disrupts a human; analyst should be sure |
| Send templated email (notification, status update) | T2 | Reaches recipients; reversibility is sending a correction |
| Publish IOC to internal TI feed (org-controlled, MISP private) | T2 | Org-internal distribution; reversal supported by feed admin |
| Publish IOC to ISAC or external partner feed | T3 | Leaves the org boundary; usually irreversible |
| Submit MITRE ATT&CK contribution | T3 | Public attribution; irreversible |
| Deliver compliance / regulatory document | T3 | Sends to regulator/customer/partner; irreversible |

### 2.1 D3FEND technique mapping

Each action type carries an optional `d3fend_technique` mapping to a MITRE D3FEND technique ID. This is illustrative metadata — used for coverage projections, reporting, and the agent loop's surfacing of "for technique T1XXX, available D3FEND-mapped actions in your environment are X, Y, Z." It is *not* enforced at authorization time; not load-bearing for control flow. Tenants and adapter authors may extend the mapping with additional action types. The mapping ships as part of the signed action descriptor distribution (05-component-architecture.md §11.1).

| Action type | D3FEND technique |
|---|---|
| `host.isolate` | D3-NTI (Network Traffic Isolation) |
| `host.unisolate` | D3-NTI (reversal) |
| `account.suspend` | D3-AL (Account Locking) |
| `account.disable` | D3-AL |
| `session.revoke` | D3-AL |
| `credential.reset` | D3-CR (Credential Rotation) |
| `process.kill` | D3-PT (Process Termination) |
| `file.quarantine` | D3-FR (File Removal) |
| `email.quarantine` | D3-MAR (Message Authenticity Removal) |
| `email.purge` | D3-MAR |
| `block.add` | D3-NI (Network Isolation) |
| `detection.deploy` | D3-DA (Detection Authorship) |
| `detection.retire` | D3-DA (reversal) |
| `host.reimage` | D3-RIO (Restore Image / Operating System) |
| `ioc.publish_to_misp` | D3-IDA (Indicator Distribution and Attribution) |
| `ioc.publish_to_isac` | D3-IDA |
| `ticket.create` | (not D3FEND-mapped — operational handoff, not defensive technique) |
| `comm.post` | (not D3FEND-mapped — communication, not defensive technique) |
| `document.deliver` | (not D3FEND-mapped — reporting, not defensive technique) |

---

## 3. Actions in the domain model

Actions integrate with the existing model rather than parallel to it.

### 3.1 The shape of an action: `x-action`

I introduce one new custom STIX object, `x-action`, rather than overloading `x-interpretation` with a new `interpretation_type`. Reasoning:

- `x-interpretation` is already typed by the *kind of reasoning* (`extraction`, `sighting`, `hypothesis`, `prediction`, `refutation`, `conclusion`, `lifecycle`). Adding `action` to that enum mixes two different things — reasoning *about* state and reasoning that *changes* state in the world.
- An action has a meaningful lifecycle of its own (REQUESTED → APPROVED → EXECUTING → SUCCEEDED / FAILED / REJECTED / EXPIRED), with multiple Interpretations recorded against it over time. A plain Interpretation is a single recorded act and shouldn't carry mutable state.
- Reversal needs a stable identity to point at: "this `x-action` was reversed by that `x-action`." That's much cleaner than "this Interpretation reverses that Interpretation."

So: `x-action` is a sibling primitive, **produced by** an Interpretation (the analyst or AI's reasoning that this action should happen), and its lifecycle transitions each emit further Interpretations.

The canonical `x-action` schema lives in **01-domain-model.md → CUSTOM STIX OBJECTS** (single source of truth: fields, status enum, evidence_refs as `list<EvidenceRef>`, actor model, etc.). This spec defines only the auth-specific pieces — the `Authorization` sub-record (§3.3), the `Execution` sub-record (§6.1), and the `TargetSpec` shape carried inside `x-action.targets`:

```text
TargetSpec:
  entity_ref             STIX SCO id (the thing being acted on)
  resolved_identifier    string (e.g., hostname, mailbox, account UPN —
                         what the adapter actually sends to the downstream tool)
  asset_criticality      optional string (see §10)
```

Every `x-action` has a `produced-by` edge to an Interpretation of type `action-request` (a value in the canonical `interpretation_type` enum — this *is* a kind of reasoning, even though the action itself is not). This piggybacks on the existing produced-by mechanism in the domain model and keeps the reasoning thread intact.

The `x-action` lifecycle is **event-sourced as part of the investigation aggregate** (02-persistence.md §1, §2.1, §3). The `status` field above is a projection — the canonical state machine lives in seven action lifecycle events: `ActionRequested`, `ActionApproved`, `ActionRejected`, `ActionExpired`, `ActionDispatched`, `ActionResulted`, `ActionReversed`. Same-aggregate placement means the `x-action` and its producing Interpretation are recorded in one transaction (a shared `correlation_id` ties them); no cross-aggregate consistency story is needed.

### 3.2 Lifecycle and emitted Interpretations

Each transition emits a new Interpretation linked to the `x-action`. The mapping:

```text
REQUESTED          -> APPROVED            interpretation_type = "action-approval"
                                          (mode != TWO_PARTY: solo approval terminal)
REQUESTED          -> PENDING_SECONDARY   interpretation_type = "action-approval"
                                          (mode == TWO_PARTY: primary approval only;
                                          waiting for secondary)
REQUESTED          -> REJECTED            interpretation_type = "action-rejection"
REQUESTED          -> EXPIRED             interpretation_type = "action-expiry"     (system-emitted)
PENDING_SECONDARY  -> APPROVED            interpretation_type = "action-approval"
                                          (secondary approval; both approver_refs
                                          on the Authorization record now populated)
PENDING_SECONDARY  -> REJECTED            interpretation_type = "action-rejection"
                                          (secondary declines)
PENDING_SECONDARY  -> EXPIRED             interpretation_type = "action-expiry"     (system-emitted)
APPROVED           -> EXECUTING           interpretation_type = "action-dispatch"   (system-emitted)
EXECUTING          -> SUCCEEDED | FAILED  interpretation_type = "action-result"     (system-emitted)
SUCCEEDED          -> REVERSED            recorded on the *reversing* x-action via reversal_of_ref;
                                          reversed x-action is mutated to status REVERSED
                                          and emits an "action-reversal" Interpretation.
```

The seven `action-*` types — `action-request`, `action-approval`, `action-rejection`, `action-expiry`, `action-dispatch`, `action-result`, `action-reversal` — live in the canonical `interpretation_type` enum (01-domain-model.md INTERPRETATION → Interpretation types) alongside the reasoning types.

### 3.3 Authorization sub-record

```text
Authorization:
  mode                   MANUAL | AUTO_POLICY | TWO_PARTY
  stage                  SOLO | PRIMARY | SECONDARY
                         (SOLO for MANUAL and AUTO_POLICY; PRIMARY then
                         SECONDARY for TWO_PARTY. Mirrors the
                         02-persistence.md §3 ActionApproved.authorization.stage
                         payload field; surfaced explicitly here so
                         consumers don't derive it from the presence of
                         secondary_*.)
  primary_approver_ref   Analyst id (the one who clicked confirm or whose
                         policy fired); null for REJECTED actions
  primary_approved_at    timestamp
  secondary_approver_ref optional Analyst id (for TWO_PARTY, set when
                         stage advances to SECONDARY)
  secondary_approved_at  optional timestamp
  policy_ref             optional string (policy id that auto-approved)
  policy_version         optional string (content hash of policy at time of fire)
  challenge_response     optional string (the typed confirmation string for T3)
```

For `AUTO_POLICY`, `primary_approver_ref` points at the *human who authored or last signed off on the policy*, not at "the system." This preserves the principle that every action traces to a named human.

**Actor / approver invariant.** When a lifecycle Interpretation is recorded for an action (`action-approval`, `action-rejection`, etc.), the event envelope's `actor.principal` (see 02-persistence.md §7) MUST equal the relevant approver field on the `Authorization` record:

- `MANUAL`: `actor.principal == primary_approver_ref` (the analyst who clicked).
- `AUTO_POLICY`: `actor.principal == primary_approver_ref` (the policy's signed-off-by analyst). The AI agent that originated the request is recorded as `actor.delegate`.
- `TWO_PARTY`: on the primary approval Interpretation, `actor.principal == primary_approver_ref`; on the secondary approval Interpretation, `actor.principal == secondary_approver_ref`.

This is the load-bearing tie between the authorization model here and the actor model in 01-domain-model.md. There is no path by which an AI agent or "the system" appears as a principal — every recorded action is owned by a named human.

---

## 4. Auto-approval policy model

### 4.1 Mechanism

Policy-as-code, expressed in **CEL** (Common Expression Language), evaluated by the Java backend. Reasons:

- **Rego/OPA** is the most powerful option but is overkill: SOC policies don't need package hierarchies or full Datalog. The mental cost on analysts authoring policies in Rego is real.
- **YAML-only configs** can't express the conditional logic this needs ("evidence weight STRONG and derivation DIRECT and asset class not in {prod-critical}"). The moment you start adding YAML conditional DSLs you've reinvented a worse policy language.
- **CEL** is an expression language, not a programming language; it's already used by Kubernetes admission, GCP IAM conditions, and Envoy. There are mature Java CEL evaluators (cel-java). Authors write predicates over a typed context object. Side-effect-free by construction.

A policy is a versioned object:

```text
policy:
  id                       policy/<slug>/<semver>
  action_match             list of action_type globs (e.g., "host.isolate")
  predicate                CEL expression returning bool
  effect                   AUTO_APPROVE | REQUIRE_TWO_PARTY | DENY
  shadow                   bool, default false (see §4.4 — when true, the
                           policy is evaluated and its decision recorded as
                           would_have_fired in PolicyEvaluated events, but
                           authorization falls through to the manual flow)
  secondary_approver_pool  optional list of Analyst ids (only meaningful when
                           effect == REQUIRE_TWO_PARTY; defines who can act as
                           the secondary approver. Defaults to the on-call
                           rotation when unspecified.)
  authored_by              Analyst id
  signed_off_by            list of Analyst ids (config-change governance)
  effective_from           timestamp
  effective_until          optional timestamp
  content_hash             sha256 of canonical form
```

Policies are stored in a versioned repo (git is fine for v0; the path doesn't matter for this thread) and loaded into the backend at startup and on signal. Any change requires a signed config commit. The Java backend evaluates policies in priority order: any matching `DENY` wins; else any matching `REQUIRE_TWO_PARTY`; else any matching `AUTO_APPROVE`; else fall through to the default tier flow.

### 4.2 The CEL evaluation context

```text
ctx.action.type                  string
ctx.action.tier                  "T2" | "T3" — final tier after the §1 escalator
                                 has been applied (so a T2 action targeting
                                 >threshold entities arrives here as "T3")
ctx.action.targets               list<TargetSpec>
ctx.action.target_count          int
ctx.action.parameters            object
ctx.action.requested_by.kind     "HUMAN" | "AI_DELEGATED" — matches the
                                 canonical actor.kind enum in
                                 01-domain-model.md INTERPRETATION → Actor model
ctx.action.requested_by.id       string (Analyst id; the principal — never
                                 the AI delegate, even when kind is
                                 AI_DELEGATED)
ctx.action.delegate.agent_id     optional string (the AI delegate's agent id
                                 when kind is AI_DELEGATED)
ctx.action.delegate.model        optional string (the AI delegate's model)

ctx.investigation.id             string
ctx.investigation.context        "investigation" | "hunt"
ctx.investigation.lifecycle      string
ctx.investigation.seed_kind      "alert" | "entity" | "question"

ctx.evidence.sightings           list<Sighting view>
ctx.evidence.hypotheses          list<x-hypothesis view>
                                 each with: status, supporting_sightings (with weight),
                                 refuting_sightings (with weight)
ctx.evidence.all_direct          bool — true iff every Sighting/ObservedData
                                 in evidence_refs has derivation_mode == DIRECT
ctx.evidence.has_strong_support  bool — convenience: any x-supports edge with weight STRONG
ctx.evidence.max_supporting_weight   "STRONG" | "MODERATE" | "WEAK" | "NONE"

ctx.targets.criticality_classes  set<string> — union of asset classes across all targets
ctx.targets.any_in(class)        function — true if any target is in that class
ctx.targets.all_in(class)        function

ctx.sop_guidance.applicable      bool — true if SOP retrieval surfaced
                                 relevant guidance for this action's
                                 investigation context (see
                                 06-knowledge-service.md §5.1)
ctx.sop_guidance.recommendation  optional string — extracted recommendation
                                 if SOP guidance is structured (e.g.,
                                 "isolate", "do-not-act",
                                 "require-secondary"); null when SOPs are
                                 narrative-only

ctx.similarity.has_match         bool — true if recall_similar_investigations
                                 returned ≥1 ranked result above a
                                 configured score threshold
ctx.similarity.top_match_outcome optional string — terminal state of the
                                 closest past similar investigation:
                                 "succeeded" | "failed" | "abandoned" |
                                 "inconclusive"; null if no match

ctx.time.utc                     timestamp
ctx.time.business_hours          bool (org-configured)
```

The fields are intentionally *projections* — flattened views of the domain model — not raw STIX. Policy authors shouldn't have to navigate STIX edges by hand; that's a footgun. The Java backend builds the context from the actual graph at evaluation time.

### 4.3 Concrete policy examples

**Example 1: auto-isolate on strong-evidence Cobalt Strike beacon.**

```yaml
id: policy/host-isolate-cobalt-strike/1.2.0
action_match: ["host.isolate"]
effect: AUTO_APPROVE
predicate: |
  ctx.action.target_count == 1 &&
  ctx.evidence.hypotheses.exists(h,
    h.status == "SUPPORTED" &&
    h.labels.exists(l, l == "ttp:cobalt-strike-beacon") &&
    h.supporting_sightings.exists(s, s.weight == "STRONG")
  ) &&
  ctx.evidence.all_direct &&
  !ctx.targets.any_in("prod-critical") &&
  !ctx.targets.any_in("domain-controller")
```

**Example 2: AI-delegated requests can never auto-approve a T3, ever.**

```yaml
id: policy/ai-no-tier3/1.0.0
action_match: ["*"]
effect: DENY
predicate: |
  ctx.action.requested_by.kind == "AI_DELEGATED" &&
  ctx.action.tier == "T3"
```

(`authorization_mode` is a *decision output* of policy evaluation, not a predicate input — so it doesn't appear in the predicate. The DENY here means: an AI-delegated T3 request is never auto-approved by *any* policy. The action falls through to the manual flow, where a human must explicitly approve.)

This is a baseline policy that ships with the system and cannot be deleted, only superseded by a higher-priority policy with explicit override governance. Worth being heavy-handed about: "AI cannot push to prod even if a policy says so" is the kind of invariant you want enforced at multiple layers.

**Example 3: require two-party for any action targeting domain controllers.**

```yaml
id: policy/dc-two-party/1.0.0
action_match: ["host.isolate", "user.disable", "session.revoke"]
effect: REQUIRE_TWO_PARTY
predicate: |
  ctx.targets.any_in("domain-controller")
```

**Example 4: forbid auto-approval if any evidence is INFERRED.**

```yaml
id: policy/no-auto-on-inferred-evidence/1.0.0
action_match: ["host.isolate", "email.purge", "user.disable"]
effect: DENY
predicate: |
  !ctx.evidence.all_direct
```

(Same `authorization_mode` note as Example 2: it's a decision output, not a predicate input. A DENY policy fires regardless of mode and prevents any AUTO_APPROVE policy from matching, so the practical effect is "no auto-approval when evidence isn't all direct" — the manual flow always applies.)

This encodes a defensible default: AI's evidence chains stay in advisory mode unless a human is in the loop.

### 4.4 Dry-run and shadow mode

Every policy supports a `shadow: true` flag. In shadow mode, the policy is evaluated and its decision recorded in the audit trail as `would_have_fired`, but the actual authorization falls through to the manual flow. This is essential for rolling out auto-approval policies safely — orgs run them in shadow for two weeks, review the decision log, then promote.

---

## 5. Approval flows

### 5.1 T2 — single confirm

**VS Code:** when the AI proposes a T2, the extension renders a panel with:
- Action verb and target(s) in plain language
- The cited evidence (clickable to open the Sighting / hypothesis)
- The producing Interpretation's `rationale` string
- Two buttons: `Approve (⏎)` and `Reject (⎋)`, plus a `Modify…` option that drops the analyst into a form

The action sits in `REQUESTED` until approved/rejected/expired (default expiry: 5 minutes for T2). Approval emits the `action-approval` Interpretation, the action moves to `APPROVED`, and the dispatcher picks it up.

**CLI:** the same panel rendered as a TUI prompt with the same key bindings. Non-interactive CLI sessions reject T2+ actions outright unless `--yes-i-know` is passed AND the action originated from a script the analyst is running interactively (i.e., the request came from this same TTY).

**Web (Next.js):** the review panel is the same component. Web is the pickup point for actions requested by an AI agent running asynchronously when no IDE session is attached.

### 5.2 T3 — typed confirmation

Same panel as T2 plus a challenge field: the analyst must type the action verb and target count, e.g. `purge 47 emails`. The string must match exactly. The typed string is stored in `Authorization.challenge_response`.

For policies that require `TWO_PARTY`: after primary approval the action moves to status `PENDING_SECONDARY` (a real state in the enum — see §3.1 / §3.2). A notification fires to the `secondary_approver_pool` defined on the policy — initially the on-call rotation, configurable. The secondary approver sees the same panel including the primary's approval. Both approvers must complete the typed challenge. Only the secondary's approval transitions PENDING_SECONDARY → APPROVED; rejection or expiry from PENDING_SECONDARY are also valid terminal transitions per the §3.2 lifecycle table.

### 5.3 Async approvals (Slack / email / mobile)

Out of scope to fully build in v0, but the mechanic is: the same `REQUESTED` action can have a `notification_channels` list, and the backend exposes signed deep links of the form `claude-soc://approve/<action-id>?token=<...>` that, when clicked, open the web review panel. Slack/email integrations push these links. v0 ships VS Code + CLI + web; the deep-link contract is reserved.

### 5.4 Multiple analysts watching

Each `x-action` row has an `assignee_ref` (set when an analyst opens the review panel and clicks "I'll handle this") and a `pending_approvers` set. The first analyst to approve/reject wins; the others see the panel update in real time (web socket from the Java backend). This avoids two analysts approving the same isolation simultaneously.

For T3 two-party: the primary's identity is captured at primary-approve time and that analyst is *excluded* from the secondary pool to enforce two-person integrity.

### 5.5 Minimum v0

- VS Code: full T2 + T3 panel with typed challenge
- CLI: full T2 + T3 prompts
- Web: review panel
- Two-party: works in web, deep-link-driven
- Slack/email: stubbed (deep-link contract exists, no integration yet)
- Mobile: explicitly not in v0

### 5.6 The AI/analyst boundary in the request itself

The AI agent emits an action request by calling a single tool, `request_action`, with: `action_type`, `targets`, `parameters`, `evidence_refs`, `rationale`, and `investigation_ref`. The Java backend constructs the `x-action` (in `REQUESTED`), creates the producing `x-interpretation` of type `action-request`, runs policy evaluation, and either advances state (`AUTO_APPROVE`) or surfaces in the analyst's review queue.

The AI does *not* know whether a policy auto-approved; from its perspective the call returns an action id and (if policy auto-approved) a synchronous result, otherwise pending status. This keeps AI prompts simple and means you can change policy without re-prompting the AI.

Importantly, the AI can never construct an `Authorization` record or set `status` directly — those fields are write-protected. **Enforcement lives in the investigation aggregate's command handler** (the single write path for action and interpretation events; see 02-persistence.md §2.1 and §4 for the aggregate boundary): commands whose envelope `actor.kind == AI_DELEGATED` are validated against an allowlist of fields, and `Authorization` and `status` are excluded from that list. The guard sits at the same layer as the optimistic-concurrency check, not in application code, so it cannot be bypassed by alternate code paths.

---

## 6. Failure modes

### 6.1 Execution record

```text
Execution:
  dispatched_at          timestamp
  adapter                string (which capability adapter handled the call,
                         e.g., "crowdstrike_falcon", "defender_xdr_mcp",
                         "fixture:<scenario>"; see 03-capability-layer.md §5.4)
  adapter_request_id     string (correlation id from the adapter)
  attempts               list<Attempt>
  final_outcome          SUCCEEDED | FAILED | PARTIAL | TIMEOUT
  per_target_results     map<target_index, OK | FAIL | UNKNOWN>
  raw_response_ref       optional pointer to stored adapter response

Attempt:
  attempt_no             int
  started_at             timestamp
  ended_at               timestamp
  outcome                OK | RETRYABLE_ERROR | FATAL_ERROR | TIMEOUT
  error_class            optional string
  error_detail           optional string
```

### 6.2 The categories

- **Approved, dispatch failed (network, adapter unreachable):** action stays `APPROVED`, the dispatcher retries with exponential backoff (default: 3 attempts, 2s/8s/30s). Each attempt is a row in `Execution.attempts`. After max retries: status moves to `FAILED`, `final_outcome=FAILED`, and an `action-result` Interpretation is emitted with `confidence=LOW` because the system genuinely doesn't know whether the action took effect on the target.
- **Approved, dispatched, adapter returns error:** if `RETRYABLE_ERROR` (rate limit, transient 5xx), retry. If `FATAL_ERROR` (auth, malformed request, target not found): no retry, status `FAILED`.
- **Approved, dispatched, partial success across targets:** status `SUCCEEDED` but `final_outcome=PARTIAL`. Per-target results recorded. The action is *not* re-dispatched for the failed targets automatically — partial-failure recovery requires a new action request, because re-dispatching silently violates the principle that every action is auditable on its own.
- **Timeout:** the adapter call exceeded the action-type timeout. Status moves to `FAILED` with `final_outcome=TIMEOUT`. The system explicitly does *not* infer success from timeout. The audit record makes this state visible to the analyst, who decides whether to re-request.
- **Approval expired before dispatch (rare; should mostly happen for stale T2 prompts):** status `EXPIRED`. New request required.

The key invariant: **the audit record never lies about uncertainty.** If the system doesn't know whether the host was actually isolated, the record says so. SOC teams need to make recovery decisions on accurate state, and "I think we isolated it" is worse than "we don't know."

### 6.3 Retry boundary

Retries are a property of the executor, not the user. The user-visible action lifecycle has no `RETRYING` state — that's an internal property of `Execution`. From the analyst's perspective, an action is `EXECUTING` until it terminates. This keeps the lifecycle small and means the UI doesn't need to render retry state.

---

## 7. Reversal model

Reversibility is a property of the action type, declared in a static manifest:

```text
host.isolate         reversible_by: host.unisolate
session.revoke       reversible_by: null   (session naturally restores on re-login;
                                            no inverse action exists, but the original
                                            is reversible in effect)
file.quarantine      reversible_by: file.restore
email.quarantine     reversible_by: email.release
email.purge          reversible_by: null   (irreversible — backup restore is out of band)
detection.deploy     reversible_by: detection.retire
user.disable         reversible_by: null   (the disable record is permanent in the audit
                                            sense; re-enabling is a new authorization decision)
```

For action types with a `reversible_by`:

- The system tracks which actions are currently in `SUCCEEDED` state and reversible. The UI exposes a "reverse this action" affordance on the action detail.
- Reversal is itself an action and goes through the same authorization flow. Critically, **reversing an action is the same tier as the original, not lower.** Un-isolating a host is also T2; pushing a "retract" detection is also T3 (because retracting a rule has the same blast radius as deploying one — anything that detected on it stops firing).
- The reversing action carries `reversal_of_ref` pointing at the original. On success, the original action's status moves to `REVERSED` and `reversed_by_ref` is populated.
- Reversal of an irreversible action is structurally impossible: there's no `reversible_by`, so the affordance never appears. Recovery (e.g., restoring purged email from backup) is a separate operation outside this system.

### Effect-based vs action-based reversal

I considered modeling "the host is currently isolated" as durable state on the entity (an `x-isolation-state`) so reversal could target the *state* rather than the *action*. Rejected for v0: the system isn't the source of truth on entity state in the world (the EDR is). Reasoning over a mirrored state field invites drift. Tracking reversal at the action level is honest: "we took this action and have not yet taken its inverse." If the host was un-isolated out-of-band by the EDR admin, that's not our reversal but it's also not pretending to be.

---

## 8. Targeting and blast radius

### 8.1 Target resolution

Every `TargetSpec` has both an `entity_ref` (STIX id, stable across investigations) and a `resolved_identifier` (what the adapter actually sends to the downstream tool — hostname, UPN, mailbox SMTP, etc.). The resolution happens at request time and is *frozen* into the `x-action`. This matters because:

- The same STIX entity can resolve differently in different environments (a hostname can change FQDN).
- An attacker watching telemetry shouldn't be able to manipulate resolution between request and execution.
- The audit record needs to capture exactly what string was sent to the tool.

### 8.2 Blast radius and asset criticality

Blast radius enters policy at two points: the T2→T3 escalator (§1) and as inputs to CEL predicates (§4.2).

Asset criticality (`prod-critical`, `domain-controller`, `pii-bearing`, etc.) is **out of scope for this thread** in terms of how it's *populated*. It's an asset-management problem and depends on org-level integrations (CMDB, identity provider attributes). For this thread:

- We assume an `asset_criticality` field exists on `TargetSpec`, populated by an asset-classification service.
- Policy can reference it.
- For v0 prototype, asset criticality comes from a static fixture file alongside the OCSF fixture scenarios (see 03-capability-layer.md §9). The real integration is a downstream thread.

I'd flag this as an explicit dependency for the fan-in: there's a "Asset Classification & Criticality" thread that needs to exist, even if not v0.

---

## 9. Audit trail fit into the domain model

Putting it together, an action produces this graph:

```text
[Sighting]    [x-hypothesis]     [Sighting]
     \             |                /
      \            |               /
       v           v              v
      [x-interpretation: "action-request"]
                   |
                   | produced-by
                   v
              [x-action: status=REQUESTED]
                   |
                   |  (analyst clicks approve)
                   v
      [x-interpretation: "action-approval"]
                   |
                   | references
                   v
              [x-action: status=APPROVED]
                   |
                   v
              [x-action: status=EXECUTING]      <- "action-dispatch" Interp
                   |
                   v
              [x-action: status=SUCCEEDED]      <- "action-result" Interp
```

Properties this graph has:

- Every state transition is an Interpretation → preserves the domain model's "every reasoning act is in the thread" invariant.
- The action's evidence is reachable in two ways: directly via `x-action.evidence_refs`, and indirectly via the producing Interpretation's `input_refs`. The two are the same set, written in the same aggregate transaction (02-persistence.md §3): the `ActionRequested` event payload carries `evidence_refs` and shares a `correlation_id` with the producing `InterpretationRecorded` event. There is no cross-aggregate constraint to enforce.
- `member-of` edges from the `x-action` and all its associated Interpretations to the Grouping put the entire action history inside the investigation.
- Querying "what actions were taken in this investigation" is a single edge traversal: `Grouping --member-of-- x-action`.
- Querying "what evidence justified this action" walks `x-action.evidence_refs` directly; querying "what reasoning led to this action" walks `produced-by` to the Interpretation and then `input_refs` from there.

### 9.1 Integration with investigation Lifecycle

- No actions can be requested against `ARCHIVED` investigations. Attempts return error.
- Actions can be requested against `CONCLUDED` investigations only if the request itself is a *reversal* — this lets you un-isolate a host weeks after closing the case without reopening. The reversal is recorded against the closed investigation but the investigation does not reopen automatically. (Reopening for any other reason is an explicit lifecycle act.)
- `DRAFT` investigations cannot request external actions (T2+). They can annotate freely.

---

## 10. What's out and what's flagged

**Explicitly out, must not be assumed in this spec:**

- The mechanics of how the capability layer's adapters execute the action (03-capability-layer.md)
- Persistence and consistency (how the lifecycle transitions are stored atomically — persistence thread)
- UI rendering specifics (the panel design above is conceptual)
- Asset classification population

**Explicitly flagged back to fan-in:**

- The `interpretation_type` enum in the domain model gains seven new values: `action-request`, `action-approval`, `action-rejection`, `action-expiry`, `action-dispatch`, `action-result`, `action-reversal`. Additive, not breaking.
- The `x-action` custom STIX object is a new domain primitive, sibling to `x-hypothesis` and `x-prediction`. It needs to land in the domain model section listing custom STIX objects.
- A new edge type, `reverses`, between two `x-action`s — though this is also expressible via the `reversal_of_ref` field, the edge form is useful for graph queries.
- An assumed dependency on an "Asset Classification" thread for `asset_criticality`.
- An assumed dependency on the capability layer for the actual tool dispatch and the contract for `adapter_request_id` correlation. The capability spec covers the read side; the write-side / action-dispatch contract is explicitly deferred to a follow-on thread (03-capability-layer.md §10). Until that thread lands, action dispatch in v0 prototype runs against fixture stubs only.

---

## 11. End-to-end example

To make the spec concrete, the path of one T2 action:

1. AI agent, investigating an alert seeded from a Cobalt Strike beacon detection, runs queries (T0, no friction) and creates Sightings (T1, no friction) linking telemetry to a hypothesis `h-1: "host WIN-A14 is C2-active"` with `x-supports` weight STRONG from a Sighting whose evidence is two `OcsfEvent`s with `derivation_mode: DIRECT`.
2. Hypothesis status moves from `OPEN` to `SUPPORTED` after the AI agent's reasoning (recorded as a normal `hypothesis` Interpretation).
3. AI agent calls `request_action(action_type="host.isolate", targets=[{entity_ref: ipv4-addr--..., resolved_identifier: "WIN-A14"}], evidence_refs=[sighting-1, h-1], rationale="Hypothesis SUPPORTED with STRONG-weight direct evidence; isolation prevents lateral movement.", investigation_ref=grouping-1)`.
4. Backend creates `x-interpretation` of type `action-request` and `x-action` in `REQUESTED`. Both get `member-of` edges to the Grouping.
5. Policy engine evaluates. The "auto-isolate on Cobalt Strike" policy from §4.3 fires: status moves to `APPROVED` with `Authorization.mode=AUTO_POLICY`, `policy_ref=policy/host-isolate-cobalt-strike/1.2.0`, `primary_approver_ref=<the analyst who signed off on this policy>`. An `action-approval` Interpretation is emitted.
6. Dispatcher picks up `APPROVED`, calls the EDR via its capability adapter. Status `EXECUTING`, `action-dispatch` Interpretation emitted.
7. EDR returns success. Status `SUCCEEDED`, `action-result` Interpretation emitted with `confidence=HIGH` (tool confirmed).
8. Three days later, after investigation conclusion, the analyst un-isolates the host: a new `x-action` of type `host.unisolate` with `reversal_of_ref` pointing at the original. Goes through normal T2 flow (one click confirm). On success, original `x-action.status` becomes `REVERSED`.

Every step lives in the reasoning thread. The whole story is reconstructible by walking edges from the Grouping.

---

This spec is intended to be self-contained and implementable as written. The two pieces it relies on from other threads — capability layer for execution, asset classification for criticality — are flagged as dependencies rather than assumed-resolved.
