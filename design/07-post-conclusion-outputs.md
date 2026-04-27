# Post-Conclusion Outputs — Spec

## Project context

An investigation reaching CONCLUDED produces more than a Report. The reasoning thread, the entities pursued, the actions taken, the techniques observed — all of it is forward-useful: it feeds the tenant's known-bad lists, surfaces detection candidates, generates compliance documents, populates the knowledge service for future similarity, opens follow-up tickets in the org's existing systems, and (where appropriate) shares indicators with industry partners.

This spec defines what happens after CONCLUDED. The architectural property is that **post-conclusion is just more workflow, not more domain machinery**. The Temporal worker that handles action dispatch handles post-conclusion outputs the same way: triggered by an event in the aggregate, executing a multi-step workflow, calling capability adapters and the knowledge service, recording its work as new events on the same aggregate.

Nothing about the domain model changes for post-conclusion. The same `x-action` primitive that carries containment-class actions during the investigation carries ticketing actions after it. The same `x-interpretation` records the agent's decision to extract IOCs. The same Temporal infrastructure (05) runs the workflows. The product surface this enables — closing the loop from investigation to remediation to learning — is what justifies aatu as a SOAR successor rather than a focused investigation tool.

## Thread scope

- The export bundle: contents, format, signing
- IOC extraction at conclusion
- Candidate SOP generation (the learning loop into the knowledge service)
- Cross-investigation linkage
- Document generation for compliance
- Ticketing handoff and the integration with org systems of record
- Industry sharing (TI publication)
- The post-conclusion Temporal workflow that orchestrates all of this
- v0 / v1 / v2+ staging

## Out of scope

- The investigation domain model (01-domain-model.md)
- Persistence and event taxonomy (02-persistence.md) — this spec uses existing events plus introduces a small set
- The capability layer (03-capability-layer.md) — outputs are dispatched as actions through existing adapters
- Action authorization mechanics (04-action-authorization.md) — post-conclusion actions go through the same authorization gates
- Component topology (05-component-architecture.md)
- Knowledge service internals (06-knowledge-service.md) — this spec is the producer that fills its corpora
- Detection authoring tooling — the v2+ deferred thread; this spec sets up the data path that feeds it
- UI for any of the post-conclusion surfaces

---

## 1. Architectural commitments

**1. Post-conclusion is workflow, not new primitive.** The same Temporal worker that handles action dispatch handles post-conclusion. The same `x-action` lifecycle handles ticketing-as-action. No new STIX primitive, no new aggregate type. New outputs land as new events of existing types or as content in adjacent stores (knowledge service, archive target).

**2. Triggered, then orchestrated, then auditable.** `InvestigationConcluded` (02 §3) triggers the `PostConclusionPipeline(grouping_id)` workflow. The pipeline's steps are themselves recorded — as Interpretations on the source investigation's reasoning thread, or as new events on a thin parallel projection — so the workflow's work is inspectable in the same audit surface as the investigation that produced it.

**3. Author-pending for AI-generated content.** Outputs the system generates — candidate SOPs, draft compliance documents, suggested ticket bodies, suggested indicators for publication — enter their target stores in a *pending* state requiring human review and signoff. The system never silently publishes judgment. Outputs the system *executes* (ticketing API calls, IOC additions to the tenant's known-bad list) go through the same action authorization machinery as in-flight actions.

**4. Reuse, not duplicate.** Ticketing is an `x-action`. IOC publication is an `x-action`. Document storage is an export action. None of these get bespoke pipelines; they share the existing action authorization, dispatch, audit, and reversal machinery (04-action-authorization.md). What this spec adds is the *trigger* (post-conclusion, automatic where policy permits) and the *templating* (sourcing the action's parameters from the investigation's content).

**5. Customer choice on every path.** Every post-conclusion path is configurable per-tenant. Customers can disable IOC extraction, disable candidate SOP generation, disable ticketing handoff, disable any specific TI integration. Customers may also configure aatu to defer entirely to their existing SoR — aatu produces the export bundle, drops it into the SoR, and the org's existing post-incident processes take over from there. The architecture supports the full spectrum from "aatu is the SoR" to "aatu hands off everything at conclusion."

---

## 2. The export bundle

The fundamental post-conclusion output. Self-contained, signed, archive-ready, importable back into aatu.

### 2.1 Contents

```
investigation-<grouping-id>-<timestamp>.tar.gz

  manifest.json                    bundle metadata, version, signing details
  investigation.report.md          human-readable Markdown report (rendered from the
                                   investigation_thread projection plus the Report
                                   in ConclusionSlot)
  investigation.report.pdf         optional: PDF rendering of the same content
  events.jsonl                     full investigation event stream, one event per line,
                                   in sequence_no order
  stix-bundle.json                 STIX 2.1 bundle of every interpretation-layer node
                                   reachable from the Grouping, with edges flattened to
                                   STIX Relationship objects; per the per-tenant
                                   namespace UUID convention, ids reflect the tenant
                                   namespace; if a STIX-conformant export is requested,
                                   ids are re-derived under the global STIX namespace
                                   at export boundary
  ocsf-events.jsonl                referenced OcsfEvents (only those member-of the
                                   investigation directly or transitively via
                                   extracted-from / derived-from edges)
  side-stores/
    transcripts/<hash>.txt         Layer B transcripts (analyst opt-in to include)
    tool-calls/<hash>.json         Layer B tool calls
  knowledge/
    consulted-sops.json            SOPs cited during this investigation, full content
                                   at the version they were cited
    consulted-summaries.json       similar past investigations cited
  signatures/
    bundle.sig                     detached signature over the whole bundle's content
                                   hash
    chain.json                     signing chain (which key signed, when, on whose
                                   authority)
```

### 2.2 Properties

- **Self-contained.** The bundle can be read by any tool that understands STIX 2.1 + JSON Lines + Markdown. No aatu-specific decoder required for the primary content.
- **Signed.** The whole bundle's content hash is signed at conclusion time. The signing key is the tenant's signing key (held in the tenant's vault path in SaaS, or generated and stored in OS keychain for solo). Verification is independent of aatu.
- **Reimportable.** A bundle exported from one aatu deployment can be imported into another (with the matching tenant namespace UUID, otherwise as a personal-scratch import). This is the same mechanism the lift path (05 §9) uses internally.
- **Optionally redacted.** Tenants may configure Layer B transcripts to be omitted or hash-only-stubs in exports. Useful for compliance scenarios where prompt content cannot leave the production system.

### 2.3 Bundle generation workflow

`ArchiveInvestigation(grouping_id)` Temporal workflow (05 §3.3):

1. Load the investigation's projection and reasoning thread
2. Load referenced STIX nodes and edges; transitively expand member-of, extracted-from, derived-from, produced-by relationships up to the bundle scope
3. Load referenced OcsfEvents (those backing the included STIX nodes)
4. Load referenced Layer B side stores (subject to tenant policy on inclusion)
5. Load consulted SOPs and summaries from the knowledge service
6. Render the Markdown report from the thread
7. Compute the bundle's content hash
8. Sign with tenant signing key
9. Write to the archive target (S3 in SaaS, configurable bucket per tenant; local filesystem in solo by default, configurable to S3-compatible target)

Triggered automatically on `InvestigationConcluded` (configurable per tenant; default on) and on-demand via `aatu investigation export <grouping-id>`.

### 2.4 Archive target

- **Solo default.** `~/.aatu/archive/<tenant-namespace>/<grouping-id>-<timestamp>.tar.gz`
- **Solo configurable.** Any S3-compatible target the analyst configures (their org's archival bucket, MinIO instance, etc.)
- **SaaS default.** Per-tenant S3 prefix in aatu-managed storage, with tenant-controlled retention policy
- **SaaS configurable.** Customer's own S3 bucket via cross-account role; aatu writes, customer owns the bytes

The archive target is *separate from* the operational side stores. Operational stores hold active-investigation transcripts and tool-call data; the archive target holds finalized signed bundles for long-term retention and external consumption.

---

## 3. IOC extraction

Concluded investigations produce indicators worth feeding back into the tenant's defensive posture: the C2 domains observed, the file hashes, the malicious IPs, the attacker user-agent strings, the registry keys created by the malware.

### 3.1 Extraction workflow

`ExtractIOCs(grouping_id)` step within the post-conclusion pipeline:

1. Walk the investigation's STIX nodes for entities of types worth treating as IOCs:
   - `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file` (by hash), `email-addr` (in BEC contexts)
   - Excluded: `x-host`, `user-account`, `process` (these are local entities, not transferable indicators)
2. Filter to entities with at least one Sighting or Indicator-via-detection-finding linkage and a non-trivial confidence
3. For each, compute the proposed IOC record:
   - Value (the canonical identifier)
   - Type (matches STIX SCO type)
   - Confidence (mapped from supporting Sightings' weights and Indicator confidence)
   - First observed / last observed (from ObservedData range)
   - Context (which investigation, which hypothesis, which technique)
   - Suggested action (block, alert-only, watch)

### 3.2 Tenant known-bad list

The proposed IOCs land in the tenant's known-bad list as candidates pending review. The list is itself a data structure consumable by the capability resolver — when read-side capability calls return entities matching known-bad list entries, the resolver flags them in the `degradation_notes` (or in a structured way for the agent loop).

`tenant_admin` or `analyst` reviews candidates, promotes to active or rejects. Promoted IOCs are immediately effective in the resolver's matching.

### 3.3 Optional TI publication

Tenants may configure post-conclusion IOC publication to external TI platforms (MISP, OpenCTI, internal feeds, ISAC submissions). Publication is an `x-action` of type `ioc.publish_indicator`, gated through the same authorization machinery as any other action — `ti_admin` or `senior_approver` typically authorizes; `ioc.publish_to_isac` is T3 by default because it leaves the org boundary.

The action's evidence_refs cite the investigation that produced the IOC; the audit trail captures who authorized publishing. Reversal is type-specific: TI platforms with a delete API support reversal; ISAC publications are typically irreversible.

### 3.4 Per-IOC governance

Some IOCs are too sensitive to publish externally — those tied to internal-only threat actor profiling, classified incidents, customer-specific events. The IOC extraction workflow applies a sensitivity filter: each candidate IOC is tagged with a `share_scope` (`internal`, `tenant`, `partners`, `industry`, `public`) inferred from the investigation's labels and the organization's configuration. Only IOCs at or below the tenant's configured publication threshold reach the publish action.

---

## 4. Candidate SOP generation

The investigation's reasoning thread contains patterns worth codifying: "the analyst (or AI) consistently checked X before Y," "for hypotheses tagged with technique Z, the supporting evidence pattern was always W." Some of these patterns are general enough to become SOPs.

### 4.1 Generation workflow

`GenerateCandidateSOPs(grouping_id)` step within the post-conclusion pipeline:

1. Load the investigation's reasoning thread and structured summary (from 06 §3.2)
2. Identify candidate-worthy patterns via LLM-assisted analysis:
   - Recurring decision points where the agent referenced existing SOPs vs reasoned from primitives
   - Novel pivots that weren't covered by any existing SOP
   - Action sequences that produced successful outcomes worth replicating
   - Communication or escalation patterns the analyst followed
3. For each pattern, draft a candidate SOP body in markdown matching the SOP authoring conventions (06 §2.1)
4. Set `applies_to` metadata from the investigation's structural fields (techniques, entity types, threat categories)
5. Submit each candidate as a new SOP in DRAFT status, flagged `source: post_conclusion_candidate`, with the source investigation's reference attached

Candidates appear in the SOP library's review queue. `sop_author` reviews, edits, accepts (promotes through the normal IN_REVIEW → PUBLISHED lifecycle) or rejects (marks the candidate as not actionable; the rejection itself is an institutional signal — too many rejections of similar candidates suggests the generator is hallucinating patterns).

### 4.2 Quality and trust

v1 candidate SOPs are rough drafts; the goal is *useful prompts for human authors*, not production-ready SOPs. The `sop_author` review is mandatory. The system never auto-promotes candidates — the architectural commitment from §1 (author-pending for AI-generated content) is non-removable.

Quality improves over operation: rejection signals tune the generator's prompts; accepted candidates' diffs against their drafts inform what good post-extraction looks like. v2+ may add automatic deduplication against existing SOPs (so the generator doesn't propose what's already published) and pattern-strength thresholds (don't propose a candidate from a single investigation; require N similar investigations to corroborate).

### 4.3 The learning loop

This is what makes aatu compounding rather than one-shot:

1. Investigation runs → reasoning thread captured
2. Investigation concludes → `GenerateCandidateSOPs` proposes drafts
3. `sop_author` reviews, refines, publishes → SOP library grows
4. Next investigation seeds → SOP retrieval includes the new SOP
5. Agent reasoning incorporates the new SOP → next investigation is sharper

The reasoning thread is the substrate; the knowledge service is the persistence layer; the candidate generation is the connector. None of this requires changes to the domain model or the persistence model — it's all workflow on existing primitives.

---

## 5. Cross-investigation linkage

Investigations rarely stand alone. The same attacker may produce multiple investigations across weeks; a campaign hits multiple tenants; a single root incident spawns secondary investigations. The architecture supports cross-investigation linkage as a v1+ feature, lightly extending the event taxonomy.

### 5.1 New event types

Additive to 02 §3. Recorded against either of the linked investigations (the linkage event lives on whichever aggregate the linker is currently operating in; the inverse linkage projects automatically).

```
InvestigationLinked
  payload:
    other_investigation_ref     grouping--<uuid> (must be in same tenant)
    relation                    "see-also" | "follow-up-of" | "spawned-by" |
                                "duplicate-of" | "supersedes"
    rationale                   string (why linked)
    interpretation_id           the producing Interpretation
```

The producing Interpretation has `interpretation_type = "linkage"` (an addition to the canonical enum in 01 INTERPRETATION → Interpretation types).

### 5.2 Automatic linkage

The post-conclusion pipeline runs a `SuggestLinkages(grouping_id)` step that calls the knowledge service's `recall_similar_investigations` against the just-concluded investigation and proposes likely linkages. Each proposed linkage requires `analyst` review before being recorded — the system never silently links investigations.

### 5.3 Manual linkage

`analyst` may explicitly link investigations from the IDE: "this looks like a follow-up of last week's case." Same event type, manually authored Interpretation, same audit trail.

### 5.4 Cross-investigation queries

Linked investigations enable structured queries: "show me the campaign tree starting from investigation X" walks the linkage edges. "Show me all investigations linked under technique T1486 in the last quarter" combines linkage with technique labels. These are projection queries over the aggregate event stream; no new storage shape required.

---

## 6. Document generation

Concluded investigations produce documents the org needs for compliance, customer notification, regulator filings, insurance claims. These are templated outputs sourced from the investigation's content.

### 6.1 Document templates

Templates live in a tenant-configurable library. v0+ ships with a small set of common templates:

- `internal_incident_report` — security leadership-facing summary
- `customer_notification` — for incidents affecting customer data; org-specific tone
- `regulator_breach_notification` — GDPR / state-AG / SEC 8-K shapes
- `insurance_claim_evidence_packet` — cyber insurance carrier-ready packet
- `isac_submission` — for industry threat-sharing partnerships

Each template defines:
- A markdown / structured-document body with placeholder slots
- A mapping from slots to fields in the investigation projection or signed bundle
- Optional LLM-prompted fields for narrative sections ("describe the impact" → LLM generates a summary subject to human review)

### 6.2 Generation workflow

`GenerateDocument(grouping_id, template_id, parameters)` step:

1. Load the investigation projection, signed bundle, and any specified parameters
2. Render structured fields directly from the data
3. For LLM-prompted fields, call the BYOK LLM with the relevant context and the template's prompt; receive narrative content
4. Render the document, sign with the tenant key, store alongside the export bundle
5. Optionally emit a `document.deliver` action for delivery (email, portal upload, etc.) — gated through the action authorization machinery

### 6.3 Author-pending

LLM-generated narrative sections enter the document as drafts. `senior_approver` (or a tenant-configured role specific to the document type, e.g., `compliance_officer`) reviews and approves before delivery. The system never sends a regulator filing without a human's explicit signoff.

### 6.4 Retention

Generated documents are retained alongside the export bundle. Each is versioned and content-hashed. Edits create new versions; the audit trail shows what was sent when.

---

## 7. Ticketing handoff

For tenants that maintain a separate operational system (Jira, ServiceNow SOC, Linear, custom), aatu opens tickets at conclusion to drive longer-tail remediation, recovery, and post-incident work that lives in the org's existing system.

### 7.1 Ticketing as `x-action`

Per the symmetry property (05 §6.4, action types are extensible), ticketing is just another action category:

```
ticket.create        adapter operation: create_issue / create_incident
                     parameters: project, type, summary, description, assignee, labels
                     tier: T1 (no external blast radius beyond opening a ticket)

ticket.update        adapter operation: update_issue / update_incident
                     parameters: ticket_id, fields_to_update
                     tier: T1
```

Adapters for the common SoRs are first-party: `jira`, `servicenow_soc`, `linear`, `pagerduty_incidents`. Custom integrations follow the standard adapter contract.

### 7.2 Templated ticket bodies

The post-conclusion pipeline's `OpenFollowupTickets(grouping_id)` step:

1. Apply tenant-configured rules to determine which tickets to open:
   - "If techniques include T1486, open a remediation ticket in the IT-OPS Jira project"
   - "If any user-account was compromised, open a credential-reset ticket"
   - "If any host was reimaged, open a verification ticket for the IT team"
2. For each rule that fires, render the ticket body from a template using investigation content
3. Submit `ticket.create` actions through the standard authorization flow; auto-approve policies typically make this fast for low-tier ticket types

Tenants without a SoR or who prefer manual ticketing simply don't configure any rules; the step is a no-op.

### 7.3 Bidirectional linkage

When a ticket is created, the response includes the ticket id and URL. The investigation's projection is updated with a `linked_external_cases` field referencing the ticket. Future capability calls can pull updates from the ticket (`get_external_case_details`, 05 §13.2) so the investigation reflects ongoing work in the SoR.

---

## 8. Industry sharing

Optional. Customers operating in regulated or threat-aware industries (financial services, healthcare, critical infrastructure) may participate in threat-intelligence sharing through ISACs, MITRE submissions, or MISP federations.

### 8.1 Sharing as `x-action`

Same pattern as ticketing and IOC publication:

```
ti.publish_to_isac           target: list<indicator_ref>
                             parameters: isac_name, sharing_traffic_light, attribution_level
                             tier: T3 (leaves the org boundary)

ti.publish_to_misp_feed      target: list<indicator_ref>
                             parameters: feed_name, distribution_level
                             tier: T2 (org-controlled feed) or T3 (federated feed)

ti.contribute_to_attack      target: technique_ref
                             parameters: contribution_type, evidence
                             tier: T3
```

Each is gated through the standard authorization machinery; publication is irreversible by default.

### 8.2 Sensitivity gates

The sharing workflow applies the per-IOC `share_scope` filtering from §3.4. IOCs marked `internal` cannot be published; IOCs marked `industry` are eligible for ISAC submission with `senior_approver` signoff and the typed-confirmation challenge.

### 8.3 Anonymization

Where sharing requires anonymization (e.g., redacting org-identifying entity values), the action's parameters include the redaction transform applied. The published payload's content hash is recorded on the action for audit.

### 8.4 Cross-tenant within aatu

A future federated indicator pool (deferred per 01 §5) is a special case of industry sharing: aatu hosts the pool as a separate tenant-of-tenants construct, with explicit publish-and-subscribe semantics. This is v3+ at earliest and requires its own thread.

---

## 9. The post-conclusion Temporal workflow

### 9.1 Workflow definition

```
PostConclusionPipeline(grouping_id)

  trigger: InvestigationConcluded event

  steps (in order, all configurable per-tenant):
    1. ArchiveInvestigation(grouping_id)
       - Generate the export bundle, sign, store
    2. SummarizeForKnowledgeIndex(grouping_id)
       - Extract structured summary, embed, index in knowledge service (06 §3)
    3. ExtractIOCs(grouping_id)
       - Identify candidate IOCs, populate tenant known-bad list as candidates
    4. GenerateCandidateSOPs(grouping_id)
       - Identify SOP-worthy patterns, submit drafts to the SOP library
    5. SuggestLinkages(grouping_id)
       - Query knowledge service for similar investigations, propose linkages
    6. OpenFollowupTickets(grouping_id)
       - Apply tenant rules, submit ticket.create actions
    7. PublishIOCsExternally(grouping_id)
       - Where configured, submit ti.publish_* actions for high-confidence IOCs
       - Each ti.publish_* action is gated by its own authorization

  cancellation:
    - Triggered by InvestigationReopened (the conclusion is no longer terminal)
    - In-flight steps complete; subsequent steps skip
    - Already-completed effects (e.g., bundle generation) are not undone, but
      flagged as "from previous conclusion"

  failure handling:
    - Each step has its own retry policy
    - A failed step does not block downstream steps unless they have an
      explicit dependency
    - Failure events are emitted as Interpretations on the source investigation
      thread with rationale describing what failed and why
```

### 9.2 Per-step authorization

Every step that produces outputs in the world (ticket creation, IOC publication, document delivery) goes through the standard action authorization machinery. The principal recorded on each emitted action is the investigation's *concluding* analyst — the one who signed off on `InvestigationConcluded`. The delegate is the post-conclusion pipeline (recorded as a system delegate).

This preserves the audit invariant: every action traces to a named human who is responsible.

### 9.3 Audit on the source investigation

The pipeline emits `InterpretationRecorded` events on the *source investigation's* thread with `interpretation_type = "post_conclusion"` (a small addition to the canonical enum in 01). Each step's outcome is recorded — what was generated, what was published, what failed.

The source investigation's lifecycle stays CONCLUDED throughout (per 01 INVESTIGATION → Lifecycle invariants, CONCLUDED accepts new Interpretations only when they are action-* lifecycle entries for reversals; the lifecycle invariants in 01 may need a minor extension to accept `post_conclusion` Interpretations as well, to be confirmed in 01 companion edits).

### 9.4 Re-running

Tenants may re-run the pipeline against a concluded investigation (e.g., after improving the candidate-SOP generator). Re-runs produce new output versions; prior outputs are retained as superseded. Configurable per-tenant; default is "do not auto-re-run."

---

## 10. v0 / v1 / v2+ staging

| Stage | Capabilities |
|---|---|
| **v0** | Export bundle generation only. The other pipeline steps either don't apply (no real data to extract IOCs from in fixture mode) or don't exist yet (candidate SOPs require the knowledge service to be functional with real summaries). The bundle generation itself is fully functional at v0. |
| **v1** | Full pipeline: archive bundle, summary extraction, IOC extraction, candidate SOPs, linkage suggestion. Real integrations enable ticketing handoff and IOC publication via `x-action` types. Document generation for the common templates. |
| **v2** | SaaS launch: the pipeline runs in the multi-tenant Temporal cluster; per-tenant configuration becomes a tenant-admin UI surface; cross-investigation linkage events become first-class queryable; campaign-level visualization becomes possible. |
| **v3+** | Federated indicator pool (cross-tenant); detection authoring tooling formally lands as a v3 thread that consumes the same investigation event stream and reasoning thread; quality of candidate SOPs and document narratives improves with operational data. |

---

## 11. Companion edits

These small additions land alongside this spec in upstream specs:

### 11.1 01-domain-model.md

Add `linkage` and `post_conclusion` to the canonical `interpretation_type` enum in INTERPRETATION → Interpretation types. Update the Lifecycle invariants section to permit `post_conclusion` Interpretations on CONCLUDED investigations (alongside the existing exception for reversal action-* types).

### 11.2 02-persistence.md

Add `InvestigationLinked` to the v0+ event types in §3 (was deferred under "Cross-investigation linkage events" in §8 — surfaced now). The event taxonomy total moves to ~19 at v1+.

### 11.3 03-capability-layer.md

Action manifest extension in §10 (or its successor write-side adapter contract thread): include the post-conclusion action types — `ticket.create`, `ticket.update`, `ioc.publish_to_*`, `ti.contribute_to_*`, `document.deliver` — as standard categories. Adapters for common SoRs and TI platforms ship as first-party.

### 11.4 04-action-authorization.md

Action categorization table (§2) extended with the post-conclusion action types and their default tiers. No structural changes to the authorization machinery.

### 11.5 06-knowledge-service.md

Note the post-conclusion pipeline as the producer of investigation summaries and candidate SOPs. The interfaces are already specified in 06; this is just the cross-reference.

---

## 12. Open questions / Deferred to implementation

- **Default per-tenant pipeline configuration.** Which steps run by default for new tenants? Likely: archive (always on), summary extraction (always on), IOC extraction (on, candidates require review), candidate SOP generation (on at v1+), linkage suggestion (on), ticketing handoff (off; requires explicit configuration), industry sharing (off; requires explicit configuration). Confirm with first SaaS customers.
- **IOC sensitivity classification.** v0+ uses simple rules (entity type, label-based heuristics). v2+ may introduce LLM-assisted classification. The architectural shape doesn't change; quality improves.
- **Document template authoring.** Tenants will want to customize templates. v1 ships with the standard set; v2+ may add a template editor. Templates as code (markdown + YAML metadata) at v0+; templates as a managed product surface later.
- **Re-run vs new-version semantics.** When the pipeline re-runs, do superseded outputs remain visible or are they archived behind a flag? Default proposal: visible, marked as superseded; tenant-admin can prune.
- **Failure of a critical step (bundle generation) implications.** If `ArchiveInvestigation` fails, does the investigation remain in a quasi-concluded limbo, or does conclusion succeed without the bundle? Default proposal: conclusion succeeds (the aggregate state machine is authoritative); bundle generation retries independently and is auditable.
- **Pipeline cancellation on InvestigationReopened.** What happens to in-flight ticket creations or IOC publications when the investigation is reopened? Default: they complete; their outputs reference the (now-no-longer-terminal) conclusion event; the audit trail shows the reopen happened mid-pipeline.

---

## 13. Cross-references

- **01-domain-model.md** — investigation lifecycle, Interpretation types, the Report in ConclusionSlot, the actor model (post-conclusion principals)
- **02-persistence.md** — event taxonomy, projections, the same-aggregate guarantees the pipeline depends on
- **03-capability-layer.md** — action types, adapter contract, the deferred write-side thread
- **04-action-authorization.md** — authorization machinery for post-conclusion actions, reversal model, T1/T2/T3 tier mapping
- **05-component-architecture.md** — Temporal worker for `PostConclusionPipeline`, component-level deployment of post-conclusion machinery
- **06-knowledge-service.md** — summary corpus this pipeline populates, candidate SOP submission, similarity recall used in linkage suggestion

---

*End of spec.*
