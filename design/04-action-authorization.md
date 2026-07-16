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
| Disable user account (re-enableable) | T2 | v0 ships this as `account.disable` (AD/IdP vocabulary), reversible by `account.enable` |
| Re-enable disabled user account | T2 | Reversal of a T2 |
| Force MFA re-enrollment (single user) | T2 | |
| Force password reset (single user) | T2 | |
| Block hash/IP/domain at perimeter (with TTL) | T2 | |
| Remove hash/IP/domain from perimeter block list | T2 | Inverse of the block, linked at BEST_EFFORT reliability (§7.1) — re-opening traffic carries the same weight as blocking it |
| Quarantine single email from one mailbox | T2 | Restorable from quarantine |
| Push detection rule to production | T3 | Always |
| Delete email from mailboxes (purge) | T3 | |
| Deprovision user account (terminal — delete/deactivate, not re-enableable) | T3 | Distinct from the re-enableable `account.disable` above |
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

**Authoritative source of truth.** The `action_type` strings, tiers, and reversibility of the *dispatchable* v0 catalog live in code — `action.DefaultActionCatalog()` (`action/descriptor.go`), pinned by `TestDefaultActionCatalog_Frozen`. This table is the broader **roadmap taxonomy**; where a row overlaps the frozen v0 subset it MUST match the code (the v0 rows are marked ✅ below). D3FEND ids are real MITRE technique ids (`d3fend.mitre.org`). Reversal actions carry a D3FEND id only where the ontology's Restore tactic names the restoration as a first-class technique (D3-RNA on both `host.unisolate` and `ioc.unblock`, D3-RE, D3-ULA, D3-RF — a Restore technique may map to more than one reversal); reversals without a Restore-tactic home carry none.

| Action type | D3FEND technique | v0 |
|---|---|---|
| `host.isolate` | D3-NI (Network Isolation) | ✅ |
| `host.unisolate` | D3-RNA (Restore Network Access) | ✅ |
| `account.disable` | D3-AL (Account Locking) | ✅ |
| `account.enable` | D3-ULA (Unlock Account) | ✅ |
| `session.revoke` | D3-ST (Session Termination) | |
| `credential.reset` | D3-CR (Credential Revocation) + D3-RIC (Reissue Credential) | |
| `process.kill` | D3-PT (Process Termination) | |
| `process.suspend` | D3-PS (Process Suspension) | |
| `file.quarantine` | D3-FEV (File Eviction) | |
| `file.restore` | D3-RF (Restore File) | |
| `persistence.remove` | D3-RKD (Registry Key Deletion; scheduled-task analog) | |
| `email.quarantine` | D3-ER (Email Removal — reversible application) | ✅ |
| `email.release` | D3-RE (Restore Email) | ✅ |
| `email.purge` | D3-ER (Email Removal — terminal application) | ✅ |
| `ioc.block` | D3-NTF (Network Traffic Filtering); hash-flavored blocks also implement D3-EDL (Executable Denylisting) | ✅ |
| `ioc.unblock` | D3-RNA (Restore Network Access) — the inverse of `ioc.block`, linked at BEST_EFFORT reliability (§7.1 Position C) | ✅ |
| `detection.deploy` | D3-DA (Detection Authorship) | |
| `detection.retire` | — (reversal of `detection.deploy`) | |
| `host.reimage` | D3-RDI (Restore Disk Image) | |
| `ioc.publish_to_misp` | D3-IDA (Indicator Distribution and Attribution) | |
| `ioc.publish_to_isac` | D3-IDA | |
| `ticket.create` | (not D3FEND-mapped — operational handoff, not defensive technique; also the dispatch vehicle for **Handoff** dispositions, §2.2) | |
| `comm.post` | (not D3FEND-mapped — communication, not defensive technique) | |
| `document.deliver` | (not D3FEND-mapped — reporting, not defensive technique) | |

Reconciliation note (freeze): the v0 rows were corrected against the code catalog and MITRE D3FEND — `host.isolate` is D3-NI (was mis-listed D3-NTI), and the block action is `ioc.block`/D3-NTF (was the drifted `block.add`/D3-NI).

Reconciliation note (disposition pass): verified against the D3FEND tactic payloads for Isolate/Evict/Restore (`d3fend.mitre.org` API). Corrections: `session.revoke` D3-AL → D3-ST (Session Termination is first-class under Process Eviction); `file.quarantine` D3-FR → D3-FEV (File Eviction — no D3-FR exists); `host.reimage` D3-RIO → D3-RDI (Restore Disk Image — no D3-RIO exists); `credential.reset` D3-CRO → D3-CR + D3-RIC (an incident-time forced reset is revoke-and-reissue, an Evict/Restore pair — not routine rotation, which is Harden-side); the `email.*` actions are mappable after all (D3-ER / D3-RE — the earlier "no clean mapping" hedge predated checking the Evict and Restore tactics); `account.suspend` removed as redundant — v0 ships the re-enableable form as `account.disable` (AD/IdP vocabulary), reversible by `account.enable`, and the terminal T3 form is "deprovision" in the §2 tier table; reversal actions now carry Restore-tactic ids per the amended convention above.

### 2.2 Response-tactic disposition table

D3FEND's three response tactics — **Isolate** (57 techniques), **Evict** (19), **Restore** (12), counting family headers — are the ontology's full "respond" surface. The dispatchable catalog above covers a deliberate subset; this section accounts for **every** technique in those tactics so nothing is silently dropped. Each technique carries exactly one of four dispositions:

- **Action** — reckon dispatches it via `request_action` (shipped or roadmap). Criteria: discrete target entity, discrete state change, an API on the other end (EDR/IdP/mail/firewall/SOAR).
- **Reversal** — the undo half of an Action: a real catalog type at the same tier as its original (§7). D3FEND's Restore tactic is largely this column with first-class ids.
- **Handoff** — a genuine response step that is not an agent-dispatchable state change: change-managed recovery, forensically destructive operations, external legal/registrar processes. Dispatch vehicle: `ticket.create` (T1, operational handoff) with a structured payload; the investigation records the handoff, links the ticket, and the conclusion notes residual state. D3FEND-mapped in the *record*, not the dispatch.
- **Architecture** — preventive/posture controls that share a tactic with response techniques but have no incident-time dispatch. Their product surface is post-conclusion recommendations (07-post-conclusion-outputs.md), not the action catalog.

Family headers whose children are individually dispositioned inherit "covered via children."

**Isolate (57 — 11 Action-covered, 46 Architecture):**

| D3FEND technique(s) | Disposition | Mapping |
|---|---|---|
| D3-NI Network Isolation (family, applied per-host) | Action | `host.isolate` ✅ |
| D3-NTF Network Traffic Filtering; D3-ITF Inbound / D3-OTF Outbound Traffic Filtering | Action | `ioc.block` ✅ (traffic direction is a tool mechanism, not a distinct analyst action) |
| D3-DNSDL DNS Denylisting + children D3-FRDDL, D3-FRIDL, D3-HDDL, D3-HDL, D3-RRID | Action | `ioc.block` ✅ (domain/IP indicator; the children are resolver mechanisms) |
| D3-EDL Executable Denylisting | Action | `ioc.block` ✅ (hash indicator → EDR blocklist) |
| D3-EI Execution Isolation (family) + D3-KBPI, D3-EAL, D3-HBPI, D3-ABPI | Architecture | sandboxing/allowlisting posture |
| D3-AMED Access Mediation (family) + all 16 children (D3-SCF, D3-IOPR, D3-CTS, D3-PAM, D3-EPL, D3-WSAM, D3-LAMED, D3-RAM, D3-NAM, D3-NRAM, D3-LFAM, D3-RFAM, D3-EBWSAM, D3-PBWSAM, D3-OVAR, D3-OPR) | Architecture | access-control posture |
| D3-APA Access Policy Administration (family) + D3-LFP, D3-UAP, D3F-UGPH, D3-DTP | Architecture | permissions/trust-policy posture |
| D3-CF Content Filtering (family) + all 13 children (D3-CQ, D3-CNE, D3-CNR, D3-CNS, D3-CM, D3-CV, D3-CFC, D3-FFV, D3-FMBV, D3-FISV, D3-FMCV, D3-FMVV, D3-FCDC) | Architecture | gateway content pipeline. Note: D3-CQ Content Quarantine is the *gateway's* quarantine; the analyst-facing quarantine is `email.quarantine`, mapped via Evict/Restore |
| D3-DNSAL DNS Allowlisting, D3-BDI Broadcast Domain Isolation, D3-ET Encrypted Tunnels, D3-DNL Directional Network Link, D3-EF Email Filtering | Architecture | allowlisting/segmentation/tunnel/data-diode/mail-gateway posture |

**Evict (19 — 10 Action, 6 Handoff, 3 family headers):**

| D3FEND technique | Disposition | Mapping |
|---|---|---|
| D3-AL Account Locking | Action | `account.disable` ✅ |
| D3-CR Credential Revocation | Action | roadmap `credential.reset` |
| D3-ANCI Authentication Cache Invalidation | Action (gap) | Kerberos/token-cache purge; own type or folded into `session.revoke`'s contract |
| D3-PT Process Termination | Action | roadmap `process.kill` |
| D3-PS Process Suspension | Action (gap) | roadmap `process.suspend` — the forensics-preserving alternative to kill |
| D3-ST Session Termination | Action | roadmap `session.revoke` |
| D3-ER Email Removal | Action | `email.purge` ✅ (terminal) + `email.quarantine` ✅ (reversible) |
| D3-FEV File Eviction | Action | roadmap `file.quarantine` |
| D3-RKD Registry Key Deletion | Action (gap) | roadmap `persistence.remove` — pairs with the `x-registry-key`/`x-scheduled-task` domain entities |
| D3-DNSCE DNS Cache Eviction | Action (low priority) | endpoint flush; typically bundled into host remediation |
| D3-HR Host Reboot; D3-HS Host Shutdown | Handoff | deliberately not agent-dispatchable — destroys volatile memory evidence mid-incident; post-forensics ticket |
| D3-DKE Disk Erasure; D3-DKF Disk Formatting; D3-DKP Disk Partitioning | Handoff | rebuild operations — the manual half of the reimage flow |
| D3-DRT Domain Registration Takedown | Handoff | registrar/legal process; ticket + the `ioc.publish_*` route |
| D3-CE Credential Eviction; D3-PE Process Eviction; D3-OE Object Eviction (family headers) | covered via children | — |

**Restore (12 — 5 Reversal, 1 Action, 4 Handoff, 2 family headers):**

| D3FEND technique | Disposition | Mapping |
|---|---|---|
| D3-ULA Unlock Account | Reversal | `account.enable` ✅ (`account.disable.reversible_by`) |
| D3-RNA Restore Network Access | Reversal | `host.unisolate` ✅; `ioc.unblock` ✅ — the inverse of `ioc.block`, linked at BEST_EFFORT reliability (§7.1 Position C) |
| D3-RUAA Restore User Account Access | Reversal | umbrella: `account.enable` + credential re-issue |
| D3-RE Restore Email | Reversal | `email.release` ✅ |
| D3-RF Restore File | Reversal | roadmap `file.restore` (pairs `file.quarantine`, §7) |
| D3-RIC Reissue Credential | Action | roadmap `credential.reset` — evict-and-restore in one dispatch (with D3-CR) |
| D3-RC Restore Configuration; D3-RD Restore Database; D3-RDI Restore Disk Image; D3-RS Restore Software | Handoff | `ticket.create` to IT/infra — change-managed recovery. Boundary case: `host.reimage` is a roadmap Action (T3, MDM/EDR-dispatchable) annotated D3-RDI; the data restoration after it is the Handoff |
| D3-RA Restore Access; D3-RO Restore Object (family headers) | covered via children | — |

The shape this yields: the *dispatchable* response surface is ~15 action types, not 88 — the three tactics are dominated by posture controls (46 of Isolate's 57). Every technique that is not an Action is still accounted for: Reversals make containment retractable, Handoffs are recorded and ticketed, Architecture items surface as post-conclusion recommendations. Tenants extending the catalog (adapter authors adding action types) should assign new types a disposition here rather than growing the Action column by default.

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

The `x-action` lifecycle is **event-sourced as part of the investigation aggregate** (02-persistence.md §1, §2.1, §3). The `status` field above is a projection — the canonical state machine lives in eight action lifecycle events: `ActionRequested`, `ActionApproved`, `ActionRejected`, `ActionExpired`, `ActionDispatched`, `ActionResulted`, `ActionReversed`, `ActionReversalAttempted` (the last records an unverified reversal attempt on the original *without* a status change, §7.1). Same-aggregate placement means the `x-action` and its producing Interpretation are recorded in one transaction (a shared `correlation_id` ties them); no cross-aggregate consistency story is needed.

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
REQUESTED          -> EXECUTING           interpretation_type = "action-dispatch"
                                          (mode == EXTERNAL_DELEGATED only: an external
                                          system substitutes reckon's approval gate per
                                          §5.7; dispatch is immediate and the approval
                                          is recorded from the orchestrator's callback)
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
  mode                   MANUAL | AUTO_POLICY | TWO_PARTY | EXTERNAL_DELEGATED
                         (EXTERNAL_DELEGATED: the approval gate was held by an
                         external orchestrator that substitutes reckon's gate
                         per an opted-in SOAR_PLAYBOOK binding; see §5.7)
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

Policy-as-code, expressed in **CEL** (Common Expression Language), evaluated by the Go backend. Reasons:

- **Rego/OPA** is the most powerful option but is overkill: SOC policies don't need package hierarchies or full Datalog. The mental cost on analysts authoring policies in Rego is real.
- **YAML-only configs** can't express the conditional logic this needs ("evidence weight STRONG and derivation DIRECT and asset class not in {prod-critical}"). The moment you start adding YAML conditional DSLs you've reinvented a worse policy language.
- **CEL** is an expression language, not a programming language; it's already used by Kubernetes admission, GCP IAM conditions, and Envoy. There are mature Go CEL evaluators (cel-go). Authors write predicates over a typed context object. Side-effect-free by construction.

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

Policies are stored in a versioned repo (git is fine for v0; the path doesn't matter for this thread) and loaded into the backend at startup and on signal. Any change requires a signed config commit. The Go backend evaluates policies in priority order: any matching `DENY` wins; else any matching `REQUIRE_TWO_PARTY`; else any matching `AUTO_APPROVE`; else fall through to the default tier flow.

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
ctx.sop_guidance.recommendation  optional string — structured recommendation
                                 (e.g., "isolate", "do-not-act",
                                 "require-secondary"). Populated only when
                                 the retrieved SOP's metadata carries the
                                 optional structured `recommendation` field
                                 (06-knowledge-service.md §2.1); the SOP
                                 body is prose and is never parsed, so this
                                 is null for narrative-only SOPs

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

The fields are intentionally *projections* — flattened views of the domain model — not raw STIX. Policy authors shouldn't have to navigate STIX edges by hand; that's a footgun. The Go backend builds the context from the actual graph at evaluation time.

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

Out of scope to fully build in v0, but the mechanic is: the same `REQUESTED` action can have a `notification_channels` list, and the backend exposes signed deep links of the form `reckon://approve/<action-id>?token=<...>` that, when clicked, open the web review panel. Slack/email integrations push these links. v0 ships VS Code + CLI + web; the deep-link contract is reserved.

### 5.4 Multiple analysts watching

Each `x-action` row has an `assignee_ref` (set when an analyst opens the review panel and clicks "I'll handle this") and a `pending_approvers` set. The first analyst to approve/reject wins; the others see the panel update in real time (web socket from the Go backend). This avoids two analysts approving the same isolation simultaneously.

For T3 two-party: the primary's identity is captured at primary-approve time and that analyst is *excluded* from the secondary pool to enforce two-person integrity.

### 5.5 Minimum v0

- VS Code: full T2 + T3 panel with typed challenge
- CLI: full T2 + T3 prompts
- Web: review panel
- Two-party: works in web, deep-link-driven
- Slack/email: stubbed (deep-link contract exists, no integration yet)
- Mobile: explicitly not in v0

### 5.6 The AI/analyst boundary in the request itself

The AI agent emits an action request by calling a single tool, `request_action`, with: `action_type`, `targets`, `parameters`, `evidence_refs`, `rationale`, and `investigation_ref` (canonical tool schema in 08-write-side-actions.md §2). The Go backend constructs the `x-action` (in `REQUESTED`), creates the producing `x-interpretation` of type `action-request`, runs policy evaluation, and either advances state (`AUTO_APPROVE`) or surfaces in the analyst's review queue.

The AI does *not* know whether a policy auto-approved; from its perspective the call returns an action id and (if policy auto-approved) a synchronous result, otherwise pending status. This keeps AI prompts simple and means you can change policy without re-prompting the AI.

Importantly, the AI can never construct an `Authorization` record or set `status` directly — those fields are write-protected. **Enforcement lives in the investigation aggregate's command handler** (the single write path for action and interpretation events; see 02-persistence.md §2.1 and §4 for the aggregate boundary): commands whose envelope `actor.kind == AI_DELEGATED` are validated against an allowlist of fields, and `Authorization` and `status` are excluded from that list. The guard sits at the same layer as the optimistic-concurrency check, not in application code, so it cannot be bypassed by alternate code paths.

### 5.7 Approval gate ownership for SOAR-delegated actions

When an action dispatches through a SOAR_PLAYBOOK binding, the downstream orchestrator (Tines, Torq, etc.) may have its own approval step inside the playbook — that's how the customer's pre-reckon workflow was designed. To avoid a hidden assumption, the binding declares who owns the gate.

```text
Binding (on a SOAR_PLAYBOOK adapter):
  external_approval_substitutes_reckon   bool (default: false)
```

- **Default (`false`)** — reckon's authorization gate fires as it would for any action: policy evaluates, analyst approves (or auto-approves), only then does the SOAR playbook get invoked. Any approval step inside the playbook is the customer's choice; reckon doesn't know about it and doesn't try to coordinate with it. If the customer leaves a Slack-approval step in the playbook, the analyst will see two approval surfaces — that's the customer's call to remove the redundant gate.

- **Opt-in (`true`)** — the customer explicitly delegates the gate. reckon skips its `ActionLifecycle` approval state, dispatches immediately on AI proposal, and the playbook's own approval flow becomes the source of truth. The `Authorization` sub-record records `mode: EXTERNAL_DELEGATED` and `primary_approver_ref` is populated from the SOAR's callback once the orchestrator confirms approval. The `audit_depth: EXTERNAL` on the Execution record makes the delegated gate visible to reviewers.

Default-safe posture: most bindings double-gate naturally (reckon's gate + whatever the playbook does internally). Friction is recoverable; an unauthorized state-changing action isn't. The opt-out is per binding and requires `policy_signer` sign-off (governance-module concern in `gated` mode).

The `mode: EXTERNAL_DELEGATED` value is a fourth `Authorization.mode` value alongside `MANUAL`, `AUTO_POLICY`, `TWO_PARTY` (see §3.3) — it indicates the gate was held outside reckon and trades audit detail for delegation flexibility.

---

## 6. Failure modes

### 6.1 Execution record

```text
Execution:
  dispatched_at          timestamp
  adapter                string (which capability adapter handled the call,
                         e.g., "crowdstrike_falcon", "defender_xdr_mcp",
                         "tines_playbook:isolate_host",
                         "fixture:<scenario>"; see 03-capability-layer.md §5.4)
  adapter_request_id     string (correlation id from the adapter)
  dispatched_via         DIRECT | SOAR_PLAYBOOK (which AdapterClass route
                         was taken; DIRECT = native vendor API call,
                         SOAR_PLAYBOOK = delegated to an external playbook
                         orchestrator. See 03 for the adapter-class enum.)
  audit_depth            FULL | EXTERNAL (FULL = reckon observed every step
                         of the outbound call chain; EXTERNAL = the
                         downstream system's internal steps are opaque to
                         reckon — reviewers needing the full chain pull
                         from that system's own logs. Defaults: FULL for
                         DIRECT, EXTERNAL for SOAR_PLAYBOOK.)
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

**`audit_depth` and the SOAR boundary.** When an action dispatches through a SOAR_PLAYBOOK binding, reckon can record the call to the orchestrator (inputs, the playbook id, the final outcome the orchestrator returns) but not the orchestrator's internal steps. `audit_depth: EXTERNAL` marks the audit chain as truncated at the orchestrator boundary so compliance reviewers know they need to pull the SOAR's own logs to complete the chain. Direct vendor-API dispatch records `audit_depth: FULL` — reckon observed the whole call.

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

Reversibility is a property of the action type, declared in a static manifest as **two orthogonal fields**: `reversible_by` (the inverse action type to dispatch, if one exists) and a `reversibility` classification (`REVERSIBLE` / `BEST_EFFORT` / `IRREVERSIBLE`). Keeping them separate resolves an ambiguity a single `reversible_by: null` used to carry — "no inverse exists" and "an inverse exists but its effect can't be trusted" are different facts and now have different encodings.

```text
                     reversible_by      reversibility   notes
host.isolate         host.unisolate     REVERSIBLE      EDR reliably un-isolates
host.unisolate       host.isolate       REVERSIBLE
account.disable      account.enable     REVERSIBLE      IdP reliably re-enables (D3-ULA)
account.enable       account.disable    REVERSIBLE
email.quarantine     email.release      REVERSIBLE      mail system reliably releases
email.release        email.quarantine   REVERSIBLE
detection.deploy     detection.retire   REVERSIBLE
ioc.block            ioc.unblock        BEST_EFFORT     inverse exists, but removal may not
                                                        undo the effect (TTL lists, propagated
                                                        RPZ, partner feeds) — see below
ioc.unblock          ioc.block          BEST_EFFORT
file.quarantine      file.restore       BEST_EFFORT     EDR-dependent whether the file is
                                                        recoverable
session.revoke       null               REVERSIBLE      no inverse action — the session
                                                        self-restores on re-login
email.purge          null               IRREVERSIBLE    no inverse; backup restore is out of band
```

### 7.1 Three separable reversal features (Position C)

The reversal machinery bundles three things that are **independently gated**:

1. **The affordance** — a "reverse this action" control appears on any `SUCCEEDED` action whose descriptor has a `reversible_by`. Driven by `reversible_by` alone.
2. **The linkage** — the reversing action is its own x-action carrying `reversal_of_ref` pointing at the original (recorded at request time, always), and the original gains a back-reference when the reversing dispatch completes: `reversed_by_ref` on a verified undo, `reversal_attempted_by_ref` on an unverified one. *"Was this block ever lifted, by whom, when?"* is queryable from both sides.
3. **The status claim** — the original's status moves to `REVERSED` and `reversed_by_ref` is populated. This is a strong assertion — *"the effect was undone"* — and is the **only** feature gated on the reliability classification.

The design rule (**Position C**, the canonical model): *keep the affordance and the forward linkage for every reversible-or-best-effort action; gate only the status claim on reliability.*

- **`REVERSIBLE` original** → a fully-successful reversing dispatch marks the original `REVERSED`. We stand behind the undo.
- **`BEST_EFFORT` original** → the reversing action still dispatches and succeeds on its own terms; the original **stays `SUCCEEDED`** but records the attempt (`action.reversal_attempted` → `reversal_attempted_by_ref`). We do not claim `REVERSED`, because we cannot verify the effect is gone — unless the adapter *proves* it via the `verify` operation (§7.3). `SUCCEEDED` here honestly means "still considered in effect as far as we can prove." The analyst judges residual effect per their tooling.
- **`IRREVERSIBLE` original** → no `reversible_by`, so the affordance never appears; reversal is structurally impossible. Recovery (e.g., restoring purged email from backup) is a separate operation outside this system.

This is why `ioc.block` ships **linked** to `ioc.unblock` (affordance + forward linkage live) at `BEST_EFFORT` (no `REVERSED` claim). The earlier "standalone action, not a reversal" framing threw away all three features because there was no way to gate only the third; Position C keeps the two that are always safe.

Common to all reversible action types:

- Reversal is itself an action and goes through the same authorization flow. Critically, **reversing an action is the same tier as the original, not lower.** Un-isolating a host is also T2; pushing a "retract" detection is also T3 (because retracting a rule has the same blast radius as deploying one — anything that detected on it stops firing).
- A `PARTIAL`/`FAILED`/`TIMEOUT` reversing dispatch never marks the original `REVERSED`, regardless of reliability — you can't claim an undo that didn't fully take effect (§6.2, honest-state).

**Implementation note (v0).** The reliability gate is live end to end. The classification is **frozen onto the x-action at request time** (`ActionRequested.reversibility`, 02 §3), so the gate reads the value the analyst approved under — a later catalog edit cannot re-classify an in-flight action (fallback to the live catalog for pre-freeze actions; a lookup failure defaults to *not reliable*, the conservative choice). On a fully-successful reversing dispatch the saga emits `ActionReversed` (original → `REVERSED`, `reversed_by_ref` set) when the original is `REVERSIBLE`, or `ActionReversalAttempted` (original stays `SUCCEEDED`, `reversal_attempted_by_ref` set) when it is `BEST_EFFORT` — so the attempt is queryable from the original's side in both cases. **Deferred to Phase F:** the adapter-side `verify` operation (§7.3) that lets a `BEST_EFFORT` reversal *earn* the `REVERSED` claim per-dispatch; until a real adapter can verify, best-effort attempts terminally record as attempted-unverified.

### 7.2 Effect-based vs action-based reversal

I considered modeling "the host is currently isolated" as durable state on the entity (an `x-isolation-state`) so reversal could target the *state* rather than the *action*. Rejected for v0: the system isn't the source of truth on entity state in the world (the EDR is). Reasoning over a mirrored state field invites drift. Tracking reversal at the action level is honest: "we took this action and have not yet taken its inverse." If the host was un-isolated out-of-band by the EDR admin, that's not our reversal but it's also not pretending to be.

This is the same honesty principle Position C (§7.1) applies to the reliability gate: the `REVERSED` status is a claim about the world, so it fires only when we can stand behind it.

### 7.3 Earning the REVERSED claim: verification verdicts, not attestations

What does the `reversibility` classification actually assert? **State ownership.** When an IdP reports "account enabled: success," that response *is* proof of effect — the IdP is the sole authority on whether the account is enabled. When a firewall reports "denylist entry removed: success," that is *not* proof the block is gone — the effect propagated to places the firewall does not govern (partner feeds, downstream resolvers, TTL'd caches). So:

- **`REVERSIBLE`** = the tool owns the effect state; its success response constitutes verification. A fully-successful reversing dispatch marks the original `REVERSED`. (host.isolate, account.disable, email.quarantine.)
- **`BEST_EFFORT`** = the effect state extends beyond the tool's authority; its success response is *not* verification. The dispatch alone records `action.reversal_attempted`, never `REVERSED`. (ioc.block, file.quarantine.)
- **`IRREVERSIBLE`** = no inverse exists. Nothing to dispatch.

**How a `BEST_EFFORT` reversal can still earn `REVERSED`: the adapter reports a verification verdict.** The write-adapter contract (08 §5) includes an optional `verify` operation: after dispatching the inverse, the adapter — the component that actually talks to the tool — checks whether the effect is observably gone (e.g., queries the denylist and the propagation endpoints it knows about) and returns a per-target verdict using the existing result vocabulary (`OK` = verified gone, `UNKNOWN` = removed what I could, cannot confirm the rest, `FAIL`). A `BEST_EFFORT` reversal whose adapter verifies all targets `OK` earns `ActionReversed`; anything less records `ActionReversalAttempted`. The claim is earned per-dispatch by evidence, never granted by configuration — this deliberately replaces an earlier signed-attestation design (a standing human promise that a binding "reliably reverses"), which could rot silently when the tool's configuration changed and contradicted the honest-state principle by permitting an unverified `REVERSED`.

An adapter that implements no `verify` simply never upgrades a `BEST_EFFORT` reversal — the conservative default. Adapters cannot *downgrade* a `REVERSIBLE` action's verdict semantics, but a **binding** may still declare a `reversibility_override` toward the pessimistic end (`REVERSIBLE → BEST_EFFORT/IRREVERSIBLE`): a customer's SOAR playbook may bundle effects the descriptor's inverse can't undo (e.g., a `host.isolate` playbook that also archives the host's session log to S3 with no restore path). Downgrade is always permitted; upgrade by configuration never is.

The interface is specified now; concrete `verify` implementations land with the real vendor write adapters (Phase F). The fixture write adapter may declare verification verdicts in fixture files to exercise the path.

The `audit_depth` on the reversing action's `Execution` record is independent — a SOAR_PLAYBOOK reversal records `audit_depth: EXTERNAL` just like a SOAR_PLAYBOOK forward dispatch.

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
- A dependency on the capability layer for the actual tool dispatch and the contract for `adapter_request_id` correlation. The capability spec (03-capability-layer.md) covers the read side; the write-side / action-dispatch contract — operation declaration, idempotency, `adapter_request_id` correlation — is specified in 08-write-side-actions.md. Until it is implemented, action dispatch in v0 prototype runs against fixture stubs only (08 §9).

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
