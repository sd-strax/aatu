# 00 — Backend Binding

How the UI package in this directory binds to the reckon engine. **This sheet is the
authority layer over the package**: where a design sheet and this binding disagree, the
binding wins, because the engine's data model wins in all respects in the UI. The UI
introduces no state of record, no vocabulary, no identity computation, and no state machine
of its own — it renders engine truth and routes intents to engine commands.

Context: the package was produced from a standalone HTML prototype that necessarily faked a
backend. Its file-centric persistence model (`.inv.md` as source of truth, client-side
stores, watchers, client-computed identity) was prototype scaffolding, and this sheet
replaces it. The prototype itself has been removed — the sheets are the distillation and
stand alone: `01` is the visual contract, `02`–`07` the interaction spec, and the *data
architecture* is the engine's.

Seam rules for this subtree (they bind every sheet here):

- `design/13-workbench.md` stays authoritative for *what exists* — the surface inventory and
  phasing (`13 §4`), the workbench discipline (`13 §3`). Sheets here own how surfaces look
  and behave. A surface not in `13 §4`'s inventory is a scope change to make there first.
- Cross-references point out of this subtree (engine specs, endpoints), never into it.
- Every rendered element names its data source. An element with no serving endpoint or spec
  section is a flagged gap (§6), not an implication that one exists.

---

## 1. Authority: what replaces the prototype's persistence model

| Prototype construct | Product binding |
|---|---|
| `.inv.md` on disk as the record ("invariant I1") | The **event-sourced investigation aggregate** is the record (`01`, `02`): the Postgres event log, with unforgeable per-event actors (JWT-derived principal, issuer-stamped `delegate_kind`). The "Enhanced file view" becomes the **investigation document** — a webview rendering backend state (`GET /api/investigations/{id}`, `/thread`, `/hypotheses`, `/actions`). The portable, GitHub-renderable markdown artifact survives as an **export**: a projection the backend renders on demand (generalizing the `design/07` export path). "Paste into a ticket unedited" is an export action, not a file on disk. |
| `InvestigationStore` (client-side mutate, YAML AST merge, byte-preserving appends, atomic writes, debounce) | Deleted. The backend is the single writer of record. The client keeps a per-investigation **cache** of backend state with a monotonic sequence. The store's *fan-out shape* survives — one change event re-renders tree, status bar, and webviews — with the source swapped from file mutations to backend deltas. |
| File watcher, reconcile-on-external-edit, self-write suppression, hydrate-the-workspace | Deleted. No workspace files (`13 §3`: an investigation is not a directory — or a file). The tree lists investigations from `GET /api/investigations`. |
| Client-enforced state machines gating mutations | **Display knowledge only.** The aggregate command handler is the arbiter (approver invariant, AI write-protection, optimistic concurrency — enforced at one layer so no path bypasses them). The UI uses transition tables to decide which affordances to show; engine rejections surface verbatim, which is already the sheets' own rule ("the UI surfaces the *reason*, never a bare invalid"). |
| Client-computed entity identity (fixed-namespace UUIDv5, TS canonicalization) | Deleted. Identity is tenant-scoped UUIDv5 minted by the engine's identity resolver — the single arbiter (`03 §7`). Ids reach the UI as opaque `<type>--<uuid>` strings. The entity popover's "Deterministic ID" row displays the engine's id. |
| `POST /investigations/:id/turns` → SSE from the backend | The agent loop is **client-side by architectural commitment** (`05 §2.7`: BYOK model key never crosses to the backend; every loop call carries the AI-delegate token). Turns run through the stdio sidecar (`implementation/agent-sidecar.md`); progress arrives as `turn/*` notifications. Projection changes (action state, thread growth from other sessions) arrive on the `/api/stream` WebSocket. See §2.6. |
| Validation code catalog (`E1xx`) | The *pattern* (named, specific, analyst-readable refusal reasons) is engine behavior already; the catalog re-derives from engine rules (expiry, approver invariants, tier gates, conclude preconditions). File-integrity codes die with the file. |
| Scenario fixtures (the prototype's scripted investigation) | The reference scenario survives in the sheets (`05 §5.1` worked example, `03 §3.4` canonical plan); bind walkthroughs and demos to the shipped OCSF fixture scenario (`fixtures/lateral-movement-via-rdp/`, `03 §9`) so design review and the eval harness run the same story. |

What carries forward from the package's engineering sheet unchanged, because it matches the
built workbench discipline: the webview-is-a-renderer rule, the typed `ui.*` intent union,
sequence-checked messages with snapshot resync, size-bounded messages with raw payloads
fetched on demand, and the designed-degradation table (with its file rows deleted and its
transport rows rebound to the version-handshake and sidecar-respawn behaviors that already
exist).

---

## 2. Vocabulary and field bindings

Analysts learn state words as *meaning* (the design system says so itself). There is exactly
one vocabulary — the engine's — because the engine's words are what the audit record stores.

### 2.1 Investigation fields (the "frontmatter card" data)

| Design field | Engine source |
|---|---|
| `id` | Aggregate UUID (a display alias may exist; the id of record is the UUID) |
| `title`, `status`, timestamps | `GET /api/investigations/{id}` (`investigation_current`) |
| `verdict`, `rationale`, `verdict_at` | Verdict act — gap §6.3 |
| `seed.{type,source,id}` | The Seed extension (`01`). Alert-seeded ↔ detection-finding-rooted; hypothesis-seeded ↔ hunt |
| `entities[]` | STIX objects in the investigation's grouping. Roles (`subject/suspicious/related`) are presentation, derivable from seed + sightings |
| `evidence[]` (pins) | Pin act — gap §6.2 |
| `remediation.actions[]` | `GET /api/investigations/{id}/actions` (`action_current`) |
| `external_work[]`, `comms.*` | Phase F (§4) |
| `conclusion_ref` | The export artifact (§6.5) |
| `schema` | The `/status` `api_version` handshake (built; fails closed) |

### 2.2 Coverage (tool-call pills) — engine words, verbatim

| Design | Engine (`03 §6.1`) |
|---|---|
| `FULL` | `COMPLETE` |
| `PARTIAL` | `PARTIAL` |
| `NOT_AVAILABLE` / `NOT_CONFIGURED` | `UNAVAILABLE_TENANT` |
| — | `UNAVAILABLE_TRANSIENT` (configured but unhealthy — a distinction the sheets want and get for free) |
| `ERROR` | `FAILED` |

The package's rule "no data is information, not failure" is the engine's
`COMPLETE`-with-zero-events semantic: evidence of absence. Keep the rule; use the words.

### 2.3 Action status

| Design | Engine (`04 §3.1`) |
|---|---|
| `PENDING` / `AWAITING_APPROVAL` | `REQUESTED` (presentation labels `PENDING_MANUAL` / `PENDING_TWO_PARTY`) |
| `AWAITING_SECOND` | `PENDING_SECONDARY` |
| `RUNNING` | `EXECUTING` |
| `SUCCEEDED / FAILED / REJECTED / EXPIRED / REVERSED` | identical |
| `WAIVED` | No engine state; nearest truth is `REJECTED` with a waive-flavored rationale. Open question §7. |

**Retry binds to a new action, never the same id.** The dispatch ledger (`08 §6b`)
guarantees one x-action id never dispatches twice, and the write path is no-fall-through
(a partial state change must not be re-attempted). "Retry" = request a new action with the
same descriptor/targets carrying `retry_of` lineage (§6.6); the card renders the chain.

**Card states the sheets must add** (engine truths with no design yet):

- `PARTIAL` — multi-target honest residual (`08 §6c`: failure never infers success;
  unresolved targets are `UNKNOWN`). Needs a per-target outcome list.
- **Reversal-attempted** — BEST_EFFORT reversibility (`04 §7.1`): the original stays
  `SUCCEEDED` with `reversal_attempted_by_ref`; never a claimed undo. Distinct from
  `REVERSED`. (`ioc.block` is the canonical BEST_EFFORT case.)
- **Expiring / expired** — approval windows are frozen at request time and lazily enforced:
  the status may still read `REQUESTED` while the engine refuses the approve. Built interim:
  `EXPIRED` badge, zero affordances, "re-request if still needed." The card needs the
  designed version, and the summary bar should surface nearest-expiry.
- **Blast-radius escalation** — a T2 action over the target threshold becomes T3
  (non-negotiable, `04 §1`); the card should say *why* ("escalated: N targets").

### 2.4 Lifecycle

Engine states: `DRAFT / ACTIVE / PAUSED / CONCLUDED / ARCHIVED`. The sheets'
`VERDICT_REACHED` and `REMEDIATING` bind as **derived presentation states** — ACTIVE with a
recorded verdict act; ACTIVE with non-terminal actions — the same derived-flag pattern as
lazy expiry, so every surface stays truthful without new aggregate states. The package's
central thesis survives whole: *verdict is the midpoint; the investigation stays open until
every action is terminal.* Verdict preconditions (evidence required) and conclude
preconditions (all actions terminal) are enforced engine-side (§6.3).

### 2.5 Tiers and approval

- **T3 = typed challenge** (`04 §5.5`). Two-party is an *authorization mode*
  (`TWO_PARTY` → `PENDING_SECONDARY`) assigned by Gate 2 policy — orthogonal to tier and
  phased per `13 §4`. The second-approver strip renders on mode, whatever the tier.
- The sheets' typed-challenge phrasing — type the action summary to confirm — is adopted
  (better than a generic challenge input; compatible with `challenge_response`).
- "Auto-approved by policy" badge ↔ `AUTO_POLICY` + `policy_ref`/`policy_version`, already
  recorded on the approval.
- Batch approval ("Approve all T2") = N individual approvals fanned out, each its own audit
  event and card. There is no cross-action execution ordering (dispatches are independent
  workflows); the sheets drop the "watch containment land in order" sequencing claim.
- The full T2/T3 write path (request → Gate 2 → typed challenge → durable dispatch → honest
  result → reversal) is live engine + workbench behavior; the sheets bind to it directly.

### 2.6 Streaming

| Design event | Real channel |
|---|---|
| `text.delta` | `turn/text_delta` (built; word-batching is a render choice over real deltas — never simulate pacing) |
| `tool.status` / `tool.result` | `turn/tool_call` / `turn/tool_result`, with engine-distilled coverage + event count |
| `step.begin/end` | Per-round markers — gap §6.4 |
| `file.append` | Derived client-side: document and export render from the same events |
| `action.state` | `/api/stream` WebSocket projection deltas |
| `confidence` | Replaced — see §5 |
| `comms.event` | Phase F (§4) |

The `calling → received → normalizing → done` status choreography is deleted: the capability
layer's invoke+normalize is one span, and animating stages that did not happen violates the
package's own honesty rule. Render real stages only.

### 2.7 Hypotheses

Engine statuses, verbatim: `PROPOSED / OPEN / SUPPORTED / REFUTED / INCONCLUSIVE /
ABANDONED` — and **predictions**: falsifiable test conditions with per-prediction status and
test-result refs (`01`; served by `/hypotheses`). The hypothesis card grows a prediction
sublist; the flat open/supported/refuted list in the sheets is superseded.

### 2.8 Entities

- Type mapping: `file-hash` → STIX `file` (hashes are properties, not a type); `alert` →
  detection finding (Indicator + Sighting, `03 §4.12`).
- **Process identity is the instance, not the image name**: `(host, pid, created_time@1s)`,
  a deliberate STIX deviation (`03 §7`). Process chips render host-qualified; the image name
  is a pivot query, not an identity. (Basename identity would collapse every `powershell.exe`
  everywhere into one entity and make cross-investigation appearance counts meaningless.)
- Aliasing is linked, never merged — matches the engine's alias edges exactly, including the
  popover copy ("not surveillance, just join keys").
- Cross-investigation appearances are a backend query — gap §6.1.

---

## 3. Adopted from the package (supersedes current workbench rendering)

1. **The tool-call block as the trust primitive** — collapsed one-liner → query / normalized
   summary / raw JSON, coverage pill, pin action, independent fan-out resolution. Replaces
   the current disclosure rows.
2. **The entity chip system** — fixed per-type palette everywhere, mono-for-data, chip →
   popover → pivot *stages a question in the composer* rather than firing.
3. **The density and token system** ("Bloomberg, not Apple") with the VS Code
   theme-variable derivation strategy.
4. **Designed degradation and empty states** — normal states with a designed appearance,
   never a stack trace.
5. **The seed picker** — an investigation always begins from something concrete
   (entity-rooted seeds, `01`); never an empty chat. Hypothesis seeds are in scope (hunts).
6. **Streaming discipline** — p50-to-first-token as an acceptance criterion; never block on
   the slowest tool; failures are non-blocking.
7. **Verdict-as-midpoint** — as derived states per §2.4.

---

## 4. Comms, follow-up, escalation — Phase F, on the action layer

The comms subsystem has no engine today and re-phases onto the write path when its phase
comes: an outbound message is a **T1 action** (`notify.*` descriptors + a comms write
adapter) — the mandatory pre-send preview *is* the T1-weight approval surface; follow-up
timers are Temporal timers (the expiry-emitter pattern); escalation policies join the Gate 2
policy family (versioned, audited, surface-prompts-never-auto-fire); inbound replies are a
new ingestion seam; open threads become a conclude-gate input alongside terminal actions.
Policies are tenant configuration served by the backend, not a workspace file. Every card
and flow in the comms sheet carries forward; only the phase and the data authority move.

---

## 5. Replaced elements

- **The confidence meter (percentage bar)** — no calibrated percentage exists to display;
  an invented one is fabricated precision. Replaced by coverage-derived categorical
  statements ("2 of 2 applicable tools answered · COMPLETE · 1 not configured") plus, where
  a confidence word is wanted, the interpretation's committed `HIGH/MEDIUM/LOW`.
- **Staged tool-status animation** — see §2.6.
- **Model pickers as hardcoded enums** — model choice is agent configuration, not a
  package.json enum.
- **Client-side identity, stores, watchers, file machinery** — see §1.

---

## 6. Engine gaps this package motivates (build list)

1. **Cross-investigation entity appearances** — endpoint over `stix_objects` + grouping
   membership; powers the popover's "appears in N other investigations."
2. **Evidence pinning** — specified: the `evidence-pin` interpretation type (`01`
   INTERPRETATION → Pinned evidence). The pinned list is a fold over non-superseded pins;
   un-pin = supersession. Remaining work is implementation (aggregate + projection +
   endpoint + surfaces).
3. **Verdict act** — specified: the `verdict` interpretation type (`01` INTERPRETATION →
   Verdict). Disposition of record, revisable by appending; requires cited evidence + ≥1
   pin; conclude requires a verdict (`01` Lifecycle invariants). AI-delegated verdicts are
   **denied by default behind a tenant configuration dial** (default-deny + configurable
   opening, the `04 §4` family; same posture as hypothesis adjudication mode) — the door to
   AI verdicts stays open by config, never by code change, and the enabling config ref rides
   the audit event. Remaining work is implementation.
4. **Per-round `step` markers** on the sidecar notification channel (additive; no protocol
   break).
5. **Live markdown export** — generalize the `design/07` export from post-conclusion to
   any-time. This is what makes the portable investigation artifact real; the package's file
   schema is repurposed as the export format specification.
6. **`retry_of` lineage** on action requests (renders the retry chain per §2.3).
7. **Raw evidence in reach** — read-only OCSF JSON via reckon URIs from cited refs
   (`13 §7` step 6; `02 §2.8` is its UI — every citation opens).
8. **Real seeds** — `CreateInvestigation` currently takes a title only; the Seed extension
   (`01` Extension 1: alert / entity / hypothesis seeds) is unimplemented, so the seed
   picker (`02 §2.7`) has nothing to bind to and "never start from an empty chat" is not
   yet true on either side. Entity-rooted seeds are load-bearing: the entity dossier,
   cross-investigation joins, and alert→investigation ingestion all depend on them.
9. Phase F: comms descriptors, timers, ingestion (§4).

---

## 7. Open questions

Deliberate non-decisions, tracked here per house convention:

- **Panel vs document**: can the Investigation Panel be navigation + approvals + composer,
  with the document as the single reading surface — or are two renderings of the reasoning
  stream (panel chat + document timeline) worth the duplication? The package's own "rethink
  signal" (if analysts ignore the document, the thesis fails) is the test.
- **`WAIVED`**: is "decided not to do, without rejecting the idea" worth a first-class
  engine status, or does rejection-with-rationale cover it?
- **Layout floor**: the specified widths (~300px tree + 860px document + 446px panel) exceed
  small laptops; the ≤1440px strategy is undefined.
- **Auth surface**: sign-in/out state, the 401-refresh appearance, and the welcome view's
  sign-in affordance need design — the extension's dual-client PKCE flow is built and
  load-bearing.
- **Structural navigation**: the investigation is a graph (hypotheses, entities, evidence,
  typed edges) rendered today as a chronological log. The thread is the right *audit* lens
  but not the only *working* lens — what are the other lenses (by entity, by hypothesis,
  by event time), and how does the analyst move between them without losing place?
- **Two clocks**: investigation time (when we learned it) vs event time (when it
  happened). The event-time strip (`13 §4` Timeline, minimal at v0) needs its relationship
  to the thread designed — the reference scenario's own decisive fact is a 7-second
  event-time anomaly.
- **Mid-turn steering**: a multi-round agent turn is currently atomic (watch or cancel).
  A queued interjection the loop reads between tool rounds ("skip DNS, chase the service
  account") would change the feel from batch job to colleague — needs sidecar/agent
  design, not just UI.

(Resolved: naming. The package's original product name was a prototype-era simplification;
the product is **reckon** — command ids, config keys, and copy use the `reckon.` prefix
throughout, applied across every sheet. Resolved: the prototype itself was removed once the
sheets stood alone as the distillation.)

---

*Revision path for the sheets: delete the file-authority machinery (02 §2.1 raw/byte-accuracy
duties, 05 §5.1/5.6, impl-spec 01 §§1.1–1.2/1.8–1.9), rebind data sources per §2, adopt
engine vocabularies verbatim, add the four missing card states (§2.3), and cite each element
to its engine spec (`03 §6.1`, `04 §3/§5/§7`, `08 §6`, `01`). The visual system (01) and the
surface map (06) carry forward nearly untouched.*
