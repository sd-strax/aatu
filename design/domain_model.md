INVESTIGATION DOMAIN MODEL - SPEC FOR FAN-IN
=============================================

PROJECT CONTEXT
---------------
"Cursor for SOC analysts" - AI-native investigation environment.
Substrate: VS Code extension (primary), CLI (secondary), Java backend, Next.js frontend for collaboration views, transport-neutral capability layer for tool federation (adapters: MCP, native vendor APIs, custom integrations; see capability.md §5.4).
Personas v0: threat hunters and IR responders (hypothesis-driven, code-comfortable, latency-sensitive). Not T1/T2 triage.
Workflows v0: investigation (entity-rooted) and hunting (hypothesis-rooted) - same loop, different entry points.
Philosophy: skeleton not closed product; AI absorbs the fragmentation tax so every analyst operates with T3-level context.
v0 prototype: all adapters served by OCSF fixtures (see capability.md §9), not real tenants.


THREAD SCOPE
------------
This thread defines the domain model only - what an investigation IS as a primitive.
Out of scope (separate threads): persistence, query model, API surface, ingestion pipeline, action authorization, component architecture, capability layer (now covered by capability.md), UI projections.


DECISIONS RULED OUT (do not re-litigate)
----------------------------------------
- Notebook-cells as the underlying model (fine as a view, fights how investigations branch)
- Hand-rolling entity types instead of adopting STIX SCOs
- Embedding OCSF inside STIX as nested payload
- Embedding STIX inside OCSF
- Investigation = reasoning (investigation contains reasoning, doesn't equal it)
- A constrained bottom layer that enforces acyclicity or rigid kinds
- A pure hierarchy with one privileged containment axis


ARCHITECTURAL COMMITMENTS
-------------------------
Two-layer graph. Telemetry layer holds raw OCSF events as emitted by tools, stored verbatim, immutable. Interpretation layer holds STIX-shaped objects representing entities, observations, judgments, and reasoning, all mutable. The two layers are joined by typed edges, not embedding. One OCSF event can back many STIX nodes. One STIX entity can be backed by many OCSF events.

STIX 2.1 is the vocabulary for the interpretation layer. OCSF is the vocabulary for telemetry payloads.

Identity follows STIX deterministic UUIDv5 rules, computed within a per-tenant namespace UUID (see below). The same entity (e.g., 8.8.8.8) produces the same ID across producers and investigations within a tenant. Cross-investigation entity identity is preserved by default within a tenant. Aliasing between entities is an explicit edge, never a destructive merge.

Three deliberate deviations from strict STIX 2.1 apply to `process`, `email-addr`, and `user-account` identity computation — required for cross-tool stitching to work in real enterprise environments where every authentication system, mail platform, and EDR is case-insensitive in practice. See capability.md §7.2 for the per-type rules and rationale.

The system is multi-tenant. A tenant is a complete partition of the data: its own STIX object store, its own event stream, its own user / RBAC scope, its own adapter configuration, its own investigations, and its own namespace UUID for identity computation. Same value (e.g., `8.8.8.8`) in two different tenants produces two different STIX ids — cross-tenant identity collision is impossible by construction, not just by access control. STIX patterns (used by Indicator SDOs) operate on field values rather than ids, so explicit cross-tenant indicator sharing remains possible if and when a federated indicator pool is introduced (deferred; not v0). The tenant namespace UUID is assigned at tenant creation (a fresh UUIDv4) and immutable thereafter; changing it would re-id every node in the tenant. STIX is the *vocabulary* for the interpretation layer here, not the *wire format* — the per-tenant-namespace deviation is a deliberate trade in service of multi-tenant isolation, and STIX-conformant ids can be reconstructed at export boundaries if external federation is ever needed.

An investigation is a STIX Grouping plus four extensions: Seed, Lifecycle, ReasoningThread, ConclusionSlot.

The genuinely invented primitives are Interpretation (records reasoning acts: who, when, from-what, to-what, why) and x-action (state-changing operations against the world; see auth.md). Hypotheses and predictions are not separate primitives — they are outputs of Interpretations and live as STIX-shaped nodes inside the Grouping.

Bottom-layer primitives are node, edge, payload. No constraints enforced at the core. Conventions validated at consumer boundaries (ingress, API egress, AI tool calls, persistence write paths).


TELEMETRY LAYER
---------------
OcsfEvent (immutable):
  id              UUID, system-assigned
  class_uid       int, OCSF class identifier (e.g., 1007 process_activity, 3002 authentication)
  class_name      string, OCSF class name
  time            timestamp, when event occurred in the world
  recorded_at     timestamp, when ingested
  source_tool     string, source adapter identifier (e.g., "crowdstrike_falcon",
                  "splunk_es", "fixture:<scenario>"); see capability.md §5.4
  payload         object, full original OCSF payload, untouched

v0 set of OCSF classes ingested: out of scope; depends on the capability layer (capability.md §4).


INTERPRETATION LAYER
--------------------
All objects follow STIX 2.1 conventions. Identity is "<type>--<uuidv5>". Common fields (created, modified, created_by_ref) follow STIX semantics throughout.

Entity (STIX SCO). v0 types: ipv4-addr, ipv6-addr, domain-name, url, file, directory, network-traffic, email-addr, email-message, user-account, process, x-host, x-registry-key, x-scheduled-task, x-group. Canonical identifiers normalized on construction. The four `x-` types are custom SCOs covering Windows registry keys, scheduled tasks (and equivalents — cron, launchd, systemd), directory groups (AD / Entra / Okta), and host entities, which STIX 2.1 does not cover natively. Identity rules (including the three deviations noted above) are in capability.md §7.2.

ObservedData (STIX SDO):
  id                  observed-data--<uuid>
  first_observed      timestamp
  last_observed       timestamp
  number_observed     int
  object_refs         list of entity ids
  created, modified, created_by_ref (STIX standard)
  Linked to OcsfEvent(s) via "derived-from" edge.

Sighting (STIX SRO):
  id                    sighting--<uuid>
  sighting_of_ref       STIX object id (what was sighted)
  observed_data_refs    list (the evidence)
  first_seen, last_seen, count
  confidence            HIGH | MEDIUM | LOW
  description           string (rationale)
  created, modified, created_by_ref (STIX standard)

Indicator, Report, Note, Opinion: adopted unchanged from STIX 2.1.

Relationship (STIX SRO): generic typed edge between any two STIX objects. Fields per STIX standard plus provenance.


INVESTIGATION
-------------
An investigation is a STIX Grouping plus four extensions.

Grouping (substrate):
  id              grouping--<uuid>
  name            string
  description     string
  context         "investigation" or "hunt"
  object_refs     list of STIX object ids (members). Mutable: members are
                  added and (soft-)removed over an investigation's life via
                  MemberAdded / MemberRemoved events (persistence.md §3).
                  Soft removal preserves history — the change lives in the
                  event stream, not as a destructive edit to object_refs.
  created, modified, created_by_ref (STIX standard)

Extension 1 - Seed (immutable, set at creation). One of:
  AlertSeed:        alert_id, source, optional detection_finding_ref
  EntitySeed:       entity_ref (STIX SCO id)
  QuestionSeed:     hypothesis_statement (string)

Extension 2 - Lifecycle. Status state machine:
  States:       DRAFT, ACTIVE, PAUSED, CONCLUDED, ARCHIVED
  Transitions:  DRAFT -> ACTIVE
                ACTIVE <-> PAUSED
                ACTIVE -> CONCLUDED
                CONCLUDED -> ACTIVE (reopen)
                CONCLUDED -> ARCHIVED
  Invariants:   CONCLUDED requires conclusion_ref populated.
                Reopen clears conclusion_ref; prior Report preserved and
                referenced from reasoning thread.
                Each transition emits an Interpretation of type "lifecycle";
                the lifecycle event and the Interpretation are written in
                the same aggregate transaction (persistence.md §3) with a
                shared correlation_id.
                CONCLUDED accepts new Interpretations only when they are
                action-* lifecycle entries for reversal actions (see auth.md
                §9.1 — un-isolating a host weeks after closing the case
                without reopening). conclusion_ref stays set; the reasoning
                thread continues to grow with the reversal trace; the
                investigation does NOT auto-reopen. Any other Interpretation
                against a CONCLUDED investigation requires an explicit
                reopen (CONCLUDED -> ACTIVE).
                ARCHIVED accepts no new events of any kind.

Extension 3 - ReasoningThread. Ordered list of Interpretation node references. Empty thread is valid.

Extension 4 - ConclusionSlot. Nullable reference to a STIX Report object.


INTERPRETATION (records a reasoning act)
----------------------------------------
Records a single reasoning act.

Reference types used below and on x-action:
  EvidenceRef = StixId | OcsfEventId
                (typed union — a reference to either a STIX object or a raw
                OcsfEvent. Interpretation.input_refs and x-action.evidence_refs
                are both list<EvidenceRef>. Output references are always StixId
                — Interpretations produce STIX-shaped nodes only, never
                OcsfEvents.)

  id                      x-interpretation--<uuid>
  actor                   ActorRef (canonical shape; see "Actor model" below)
  timestamp               timestamp
  interpretation_type     extraction | sighting | hypothesis | support | refutation |
                          inconclusive | prediction | conclusion | pivot | lifecycle |
                          action-request | action-approval | action-rejection |
                          action-expiry | action-dispatch | action-result |
                          action-reversal | other
                          (canonical enum — see "Interpretation types" below)
  input_refs              list<EvidenceRef> — node ids reasoned over
  output_refs             list<StixId> — STIX nodes produced
  rationale               string (why this mapping was made; bounded ~500 chars
                          — terse by design. Full transcript / tool-call detail
                          lives in side stores per persistence.md §6 Layer B
                          and is referenced from the Interpretation, not embedded.)
  confidence              optional HIGH | MEDIUM | LOW

Actor model (canonical across the system):
  actor.principal         { user_id, display_name } — always a human
  actor.delegate          optional { agent_id, agent_kind, model } — the AI agent
                          if any. agent_kind distinguishes our own agents from
                          vendor agents and other delegates.
  actor.kind              derived: HUMAN if delegate is null, else AI_DELEGATED

AI is always a delegate, never a standalone principal. Every Interpretation
(and every persisted event — see persistence.md §7) records a human principal,
even when the reasoning was performed by an AI agent or imported from an
external system. The principal is who is *responsible* for the act; the
delegate is who/what *performed* it. Authorization derives from principal
permissions; the delegate may be restricted further but never broader.

Scope. The canonical ActorRef shape applies only to **invented primitives**
(x-interpretation, x-action) and to the **persistence event envelope** (see
persistence.md §7). STIX SDOs / SROs / SCOs (ObservedData, Sighting,
Indicator, Report, Note, Opinion, Relationship, x-hypothesis, x-prediction,
all SCOs) use the STIX-standard `created_by_ref` → Identity ref convention
as defined by STIX 2.1. The responsibility chain for any STIX-shaped node
runs through the Interpretation that produced it, not through that node's
own `created_by_ref`.

Interpretation types (canonical enum, referenced by all components):
  extraction        entity lifted from OcsfEvent
  sighting          Sighting created from ObservedData
  hypothesis        x-hypothesis proposed (creation; includes AI-PROPOSED → OPEN
                    acknowledgment and non-status field updates)
  support           x-hypothesis status changed to SUPPORTED
  refutation        x-hypothesis status changed to REFUTED
  inconclusive      x-hypothesis status changed to INCONCLUSIVE or ABANDONED
                    (rationale carries the distinction)
  prediction        x-prediction proposed
  conclusion        investigation concluded; final Report referenced from ConclusionSlot
  pivot             reasoning departed from one entity to pursue a related lead.
                    Underlying telemetry queries are T0; this captures the analytical
                    move so the thread shows the pivot intent, not just the data.
  lifecycle         investigation state transition (DRAFT/ACTIVE/PAUSED/CONCLUDED/ARCHIVED)
  action-request    x-action proposed (see auth.md §3.2 for full action lifecycle)
  action-approval   x-action approved (manual, auto-policy, or two-party primary)
  action-rejection  x-action denied
  action-expiry     x-action timed out unapproved (system-emitted)
  action-dispatch   x-action sent to its capability adapter (system-emitted)
  action-result     x-action terminal outcome — SUCCEEDED, FAILED, PARTIAL, TIMEOUT
                    (system-emitted)
  action-reversal   previously-SUCCEEDED x-action was reversed by a new x-action
  other             escape hatch — reasoning that doesn't fit any typed value above.
                    rationale MUST be populated. Periodic review of "other"
                    Interpretations drives new typed values when patterns emerge.

Interpretation lifecycle and correction:
- Append-only by default. An Interpretation, once recorded, is the immutable
  record of one reasoning act.
- Supersession (correction) is supported via the InterpretationSuperseded
  event (persistence.md §3): the new Interpretation becomes the current view
  in the thread, and the superseded one remains visible. There is no
  destructive deletion.


CUSTOM STIX OBJECTS
-------------------
x-hypothesis (working theory under investigation):
  id                  x-hypothesis--<uuid>
  statement           string (the claim)
  status              PROPOSED | OPEN | SUPPORTED | REFUTED | INCONCLUSIVE | ABANDONED
  parent_ref          optional x-hypothesis id (refinement)
  rooted_at_ref       optional STIX SCO id (anchor entity)
  rationale           string (why proposed)
  labels              optional list of strings (tags)
  created, modified, created_by_ref (STIX standard)

  Notes:
  - PROPOSED is initial state for AI-generated hypotheses pending acknowledgment.
  - OPEN is initial state for analyst-created hypotheses, and where AI hypotheses move on acknowledgment.
  - Evidence is not embedded - it lives as x-supports / x-refutes relationships from Sightings.
  - Status transitions are recorded as Interpretations in the reasoning thread.

x-prediction (testable consequence of a hypothesis):
  id                  x-prediction--<uuid>
  hypothesis_ref      x-hypothesis id
  statement           string (what would be observed if hypothesis is true)
  test_query          optional QuerySpec { tool, query_text, parameters }
  status              UNTESTED | CONFIRMED | DISCONFIRMED | INCONCLUSIVE
  test_result_refs    list of ObservedData or Sighting ids
  created, modified, created_by_ref (STIX standard)

x-action (state-changing operation against the world). Canonical schema:
  id                  x-action--<uuid>
  action_type         string (controlled vocabulary, e.g., "host.isolate",
                      "email.purge", "detection.deploy")
  tier                T2 | T3
  status              REQUESTED | PENDING_SECONDARY | APPROVED | EXECUTING |
                      SUCCEEDED | FAILED | REJECTED | EXPIRED | REVERSED
                      (PENDING_SECONDARY only used when authorization mode
                      is TWO_PARTY: action sits in this state between primary
                      and secondary approval. See auth.md §3.2.)
  targets             list<TargetSpec> (TargetSpec = {entity_ref: StixId,
                      resolved_identifier: string, asset_criticality?: string};
                      full TargetSpec definition in auth.md §3.1)
  parameters          object (action-specific arguments; shape determined
                      per action_type by the capability adapter contract)
  requested_by_actor  ActorRef (the actor who originated the request; see
                      Actor model above)
  requested_at        timestamp
  rationale           string (why this action — bounded ~500 chars; mirrors
                      the producing Interpretation's rationale)
  evidence_refs       list<EvidenceRef> — must equal the producing
                      Interpretation's input_refs. Same-aggregate
                      transaction guarantees this (persistence.md §3
                      ActionRequested), so no separate write-time check.
  investigation_ref   grouping--<uuid>
  reversal_of_ref     optional x-action id (if this action reverses another)
  reversed_by_ref     optional x-action id (set when this is reversed)
  expires_at          timestamp (REQUESTED state expires if not approved by
                      this time; system emits ActionExpired event)
  authorization       Authorization sub-record (see auth.md §3.3)
  execution           Execution sub-record (see auth.md §6.1)
  created, modified, created_by_ref (STIX standard)

  Notes:
  - Sibling primitive to x-hypothesis and x-prediction — has its own
    lifecycle (the status field) rather than being a single recorded act.
  - The producing reasoning is captured by an Interpretation of type
    "action-request"; subsequent state changes produce action-approval,
    action-rejection, action-expiry, action-dispatch, action-result, or
    action-reversal Interpretations. See auth.md §3.2 for the full state
    machine and §3.3 / §6 for the authorization and execution sub-records.


EDGE TYPES (v0 vocabulary, open)
--------------------------------
extracted-from    Entity        -> OcsfEvent       entity lifted from telemetry
derived-from      ObservedData  -> OcsfEvent       observation traces to raw event
sighted-in        Sighting      -> ObservedData    sighting based on observation
member-of         any STIX node -> Grouping        investigation membership
produced-by       any STIX node -> Interpretation  produced by this reasoning act
x-supports        Sighting      -> x-hypothesis    evidence supports (with weight: STRONG | MODERATE | WEAK)
x-refutes         Sighting      -> x-hypothesis    evidence refutes (with weight: STRONG | MODERATE | WEAK)
aliases           Entity        -> Entity          identity assertion
parent-of         x-hypothesis  -> x-hypothesis    hypothesis refinement
reverses          x-action      -> x-action        a reversing action negates a
                                                   previously-SUCCEEDED action.
                                                   Also expressible via x-action.
                                                   reversal_of_ref; the edge form
                                                   supports graph queries (auth.md §7)

Standard STIX relationship types (indicates, uses, targets, communicates-with, resolves-to, located-at, etc.) are also valid where applicable.


PROVENANCE (uniform on ObservedData, Sighting, Interpretation, Relationship)
----------------------------------------------------------------------------
  tool                string (source tool name, or "manual", or "ai-inference")
  query               optional string
  query_run_at        optional timestamp
  raw_record_ref      optional OcsfEvent id
  derivation_mode     DIRECT (from a tool) | INFERRED (derived/reasoned)


INVARIANTS
----------
- OcsfEvent is immutable after write.
- Every node and event belongs to exactly one tenant.
- Identity computation uses the owning tenant's namespace UUID; the namespace is immutable for the lifetime of the tenant.
- Entity identity is deterministic and stable across investigations within a tenant; cross-tenant identity is independent by construction.
- Aliasing is non-destructive and is always within a tenant; cross-tenant aliasing is not expressible.
- Investigation seed is immutable after creation.
- Investigation cannot be CONCLUDED without conclusion_ref populated.
- Every status change on x-hypothesis produces a corresponding Interpretation in the reasoning thread.
- Every node in an investigation's object_refs has a member-of edge to that Grouping.
- Every interpretation-layer node **produced within this system** has a produced-by edge to the Interpretation that created it. Imported nodes (e.g., vendor-emitted Indicators / Sightings ingested via the capability layer's `detection_finding` normalizer — see capability.md §4.12) carry no produced-by edge; their upstream attribution lives in `provenance.tool` and STIX-standard `created_by_ref` to a per-tenant vendor Identity SDO. The agent loop creates a system Interpretation only when an investigation engages with the imported node.


ADOPTED VS INVENTED
-------------------
Adopted unchanged from STIX 2.1: all SCOs, ObservedData, Sighting, Indicator, Report, Note, Opinion, Grouping, Relationship, identity rules (deterministic UUIDv5), field naming conventions, custom-object naming convention (x- prefix).

Adopted unchanged from OCSF: event classes and payload shapes, class UID system.

Adopted from working SOC tooling and IR methodology (TheHive, NIST 800-61): case lifecycle state machine, seed concept (precursor / indicator / question).

Adopted from event-sourcing patterns: reasoning thread as append-only ordered log.

Invented:
- The x-interpretation primitive (records a reasoning act)
- The x-action primitive (state-changing operations; lifecycle and authorization in auth.md)
- Custom STIX SDOs: x-hypothesis, x-prediction
- Custom STIX SCOs: x-host, x-registry-key, x-scheduled-task, x-group
  (entity types not covered by STIX 2.1 native; identity rules in capability.md §7.2)
- Custom STIX relationship types: x-supports, x-refutes, reverses
- The investigation extension structure (Seed, Lifecycle, ReasoningThread, ConclusionSlot) on top of Grouping


OPEN QUESTIONS DELIBERATELY LEFT TO IMPLEMENTATION
--------------------------------------------------
These are not domain-model gaps. The model accommodates either choice.
- Whether labels on x-hypothesis bind to a controlled vocabulary (e.g., MITRE ATT&CK technique IDs) or remain freeform
- Sharding / partitioning strategy for per-tenant data at scale (constrained by the tenant model: per-tenant scope by construction; the remaining question is operational tuning within a tenant, not global federation)

CLOSED (resolved by other specs):
- STIX promotion from OCSF is eager. Every tool response is normalized at
  ingest into ObservedData and SCOs, with the raw OcsfEvent retained as
  ground truth and re-normalizable on demand. See capability.md §4.13.
- The reasoning thread is materialized as a projection (investigation_thread)
  rebuilt from the event stream; the canonical ordering lives in the events'
  sequence_no, not in a list field on the Grouping. The Grouping's
  ReasoningThread extension is the logical view. See persistence.md §4.2.


END OF SPEC
