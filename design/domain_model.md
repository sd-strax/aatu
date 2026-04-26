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

Identity follows STIX deterministic UUIDv5 rules. The same entity (e.g., 8.8.8.8) produces the same ID across producers and investigations. Cross-investigation entity identity is preserved by default. Aliasing between entities is an explicit edge, never a destructive merge.

An investigation is a STIX Grouping plus four extensions: Seed, Lifecycle, ReasoningThread, ConclusionSlot.

The only invented primitive is Interpretation, which records reasoning acts (who, when, from-what, to-what, why). Hypotheses, predictions, and findings are not separate primitives - they are outputs of Interpretations and live as STIX-shaped nodes inside the Grouping.

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

Entity (STIX SCO). v0 types: ipv4-addr, ipv6-addr, domain-name, url, file, email-addr, user-account, process, x-host. Canonical identifiers normalized on construction.

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
  created_by_ref        analyst or AI agent

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
  object_refs     list of STIX object ids (members)
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
                Reopen clears conclusion_ref; prior Report preserved and referenced from reasoning thread.
                Each transition emits an Interpretation of type "lifecycle".

Extension 3 - ReasoningThread. Ordered list of Interpretation node references. Empty thread is valid.

Extension 4 - ConclusionSlot. Nullable reference to a STIX Report object.


INTERPRETATION (the only invented primitive)
--------------------------------------------
Records a single reasoning act.

  id                      x-interpretation--<uuid>
  actor                   ActorRef (canonical shape; see "Actor model" below)
  timestamp               timestamp
  interpretation_type     extraction | sighting | hypothesis | prediction | refutation | conclusion | lifecycle
  input_refs              list of node ids (STIX or OcsfEvent) reasoned over
  output_refs             list of STIX node ids produced
  rationale               string (why this mapping was made)
  confidence              optional HIGH | MEDIUM | LOW

Actor model (canonical across the system):
  actor.principal         Analyst { id, display_name } — always a human
  actor.delegate          optional AiAgent { agent_id, model_version }
  actor.kind              derived: HUMAN if delegate is null, else AI_DELEGATED

AI is always a delegate, never a standalone principal. Every Interpretation
(and every persisted event — see persistence.md §7) records a human principal,
even when the reasoning was performed by an AI agent or imported from an
external system. The principal is who is *responsible* for the act; the
delegate is who/what *performed* it. Authorization derives from principal
permissions; the delegate may be restricted further but never broader.

Interpretation types:
  extraction      entity lifted from OcsfEvent
  sighting        Sighting created from ObservedData
  hypothesis      x-hypothesis proposed
  prediction      x-prediction proposed
  refutation      hypothesis status changed to REFUTED
  conclusion      finding promoted, investigation concluded
  lifecycle       investigation state transition


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
- Entity identity is deterministic and stable across investigations.
- Aliasing is non-destructive.
- Investigation seed is immutable after creation.
- Investigation cannot be CONCLUDED without conclusion_ref populated.
- Every status change on x-hypothesis produces a corresponding Interpretation in the reasoning thread.
- Every node in an investigation's object_refs has a member-of edge to that Grouping.
- Every interpretation-layer node produced by reasoning has a produced-by edge to the Interpretation that created it.


ADOPTED VS INVENTED
-------------------
Adopted unchanged from STIX 2.1: all SCOs, ObservedData, Sighting, Indicator, Report, Note, Opinion, Grouping, Relationship, identity rules (deterministic UUIDv5), field naming conventions, custom-object naming convention (x- prefix).

Adopted unchanged from OCSF: event classes and payload shapes, class UID system.

Adopted from working SOC tooling and IR methodology (TheHive, NIST 800-61): case lifecycle state machine, seed concept (precursor / indicator / question).

Adopted from event-sourcing patterns: reasoning thread as append-only ordered log.

Invented:
- The x-interpretation primitive (the only genuinely new concept)
- Custom STIX objects x-hypothesis and x-prediction
- Custom STIX relationship types x-supports and x-refutes
- The investigation extension structure (Seed, Lifecycle, ReasoningThread, ConclusionSlot) on top of Grouping


OPEN QUESTIONS DELIBERATELY LEFT TO IMPLEMENTATION
--------------------------------------------------
These are not domain-model gaps. The model accommodates either choice.
- Whether STIX promotion from OCSF is eager (at ingest) or lazy (on reference)
- Whether labels on x-hypothesis bind to a controlled vocabulary (e.g., MITRE ATT&CK technique IDs) or remain freeform
- Whether the reasoning thread is materialized as a list or derived from produced-by edges plus timestamps
- Partitioning strategy for cross-investigation entity references at scale


END OF SPEC
