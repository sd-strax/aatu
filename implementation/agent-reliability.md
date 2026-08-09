# Building a workable agent — field lessons

Distilled from live road-testing of the v0 agent loop against a running stack
and a real external system of record (a ServiceNow dev instance). Companion to
`design/09-agent-behavior.md`, which owns the governing discipline (when a
behavior belongs to the engine vs. the prompt); this document records what
actually broke in the field, why, and the mechanism that fixed it — with
citations into the code. Read it before touching `agent/`.

The one-sentence summary: **a security product cannot rest on the model's
goodwill; every trust-critical property needs a deterministic mechanism that
holds when the model misbehaves — because it will, even on the strongest
tier, even when explicitly instructed otherwise.**

---

## 1. Two memories: the record is truth; the conversation is working memory

The event-sourced investigation record (events, `action_current`, hypotheses,
chronicle — `design/01`, `02`) is the source of truth. The model's conversation
is **disposable working memory** rebuilt from that record. Everything below
follows from taking this seriously.

Corollary: discarding the model's context loses *zero* investigative state —
which is what makes an analyst-facing "reset" safe to offer at all (§5).

## 2. Narrative poisoning is real, self-reinforcing, and tier-independent

**Field evidence.** In one long session the model: fabricated action ids that
existed nowhere; narrated "created and verified against the engine" on turns
where the tool-call ledger shows **zero tool calls**; and, when told directly
to "reconcile with actual state," produced a *fresh* fabrication (a FAILED
action described as "REQUESTED, live"). This happened on the strongest
available model tier, with explicit honesty rules already in the system
prompt. The mechanism is structural, not a model quirk: the transcript is the
model's memory, so one unverified success claim becomes "fact" for every
later turn — each turn stays *consistent with the story* rather than with the
record. A clean context on the same model behaved correctly.

**Lesson.** Prompt rules are necessary but not sufficient. The escalation
ladder that works:

1. **Prompt rules** (`agent/prompt.go` "Authority boundaries": *an action
   exists ONLY if request_action returned an action_id*; guarded by
   `agent/prompt_test.go` so they can't be silently edited away) — reduce the
   rate;
2. **Deterministic in-loop guards** (§3, §4) — bound the damage;
3. **Analyst controls** (§5) — recover when drift happens anyway.

Never stop at step 1 for anything trust-critical.

## 3. Guards must assert engine facts, never judge prose

Deterministic guards work because they only state what the engine knows to be
true — they never interpret the model's prose, so they can't themselves be
wrong:

- **Cited-id reconciliation** (`agent/reconcile.go` `reconcileActionClaims`):
  every action id the final text mentions gets its real status appended —
  `[engine record — authoritative…: dd4352b1=FAILED, 7c3e0f9b=NOT ON RECORD]`.
  No NLP; just a lookup per id. *Don't cry wolf:* a cited full-UUID that the
  engine itself produced — an observed-data ref from a read verb, an entity id,
  the investigation id quoted from a ticket body — is **not** flagged; the guard
  suppresses ids in the session's seen set (`Session.seenIDs`, fed by
  `rememberIDs` from every tool result + the investigation id) and speaks only
  for real action ids and genuinely-unknown tokens. The read verbs surfaced this:
  before them the model rarely printed non-action UUIDs, so the blunt "any UUID
  not in the action log → NOT ON RECORD" read as fabrication on legit refs — the
  runtime counterpart of the eval's G4 ground-truth (`design/10 §3`), which
  already checked *all* engine-produced ids.
- **No-action attestation** (`noActionAttestation`): prose claims a creation
  on a turn with zero successful `request_action` calls → append
  `[engine record: NO action was requested this turn]`. The trigger regex is
  deliberately generous — safe, because the appended sentence is true by the
  loop's own bookkeeping regardless of a false-positive match. *Design rule:
  when a guard's output is always-true, generous triggering is free; when it
  would judge, don't build it.* One refinement the read verbs forced: **quoted
  external data is stripped before the check** (`quotedSpan`) — a ticket body a
  read verb returned (`Description: "reimage request … incident ticket"`) is not
  the model's own creation claim, so relaying it must not trip the attestation on
  a benign read turn.
- **The correction must enter the model's own history** (`agent/session.go`,
  end of `Turn`): the footer is folded into the assistant message, not just
  shown to the analyst — otherwise the next turn compounds the uncorrected
  story. This is the anti-poisoning half of the mechanism.

A second-model "adversarial auditor" was considered and deliberately deferred:
an auditor model can hallucinate; the deterministic stack can't. Escalate to
it only if this stack proves insufficient.

## 4. Re-anchor on ground truth periodically, don't just correct

Corrections are reactive; drift is continuous. Every `anchorEveryTurns` (5)
turns — and immediately after a reset — the engine's authoritative action
record rides the user message (`engineStateAnchor`): `[engine state — the
authoritative action record… (trust THIS over any earlier narration): …]`.
Deterministic, compact, and it outweighs stale narration precisely where the
model looks first: recent context.

## 5. Give the analyst a reset — durable, visible, and non-destructive

`Session.ResetContext` (sidecar `resetSession`, workbench **Reset Agent
Context** on the investigation row) rebuilds the working context purely from
the record. Three properties earned by field pain:

- **Durable.** The reset writes a `context reset:` marker to the reasoning
  thread, and `rehydrate` (`agent/session.go`) refuses to replay transcripts
  from before the newest marker. Without this, the next sidecar respawn
  silently re-imports the discarded narration and the reset evaporates.
- **Visible.** The chronicle renders the marker as a boundary line
  (`workbench/src/investigationDocument.ts` `.ctxreset`): the analyst must be
  able to see which statements predate the re-grounding.
- **Non-destructive.** The scrollback (including the model's fabrications,
  with their correcting footers) is audit evidence and stays. Destroying the
  record of what the agent claimed would be the same sin as the claim.

## 6. Make "said vs. did" provable in seconds

The fabrication diagnosis was settled by two tables, not by debate:

- `ai_tool_calls` (`aggregate/migrations/0004_side_stores.up.sql`) — every
  tool dispatch with args and timestamps. *A turn that claims "created and
  verified" but has no rows here is a confabulation, full stop.*
- `action_current` — what actually exists and its lifecycle status.

Treat this observability as first-class: when an agent claim smells wrong,
query the ledger before theorizing. The side stores exist for compliance
(`design/02`), but their day-to-day value is exactly this.

## 7. Be liberal in what the loop accepts from the model, strict toward the engine

Models malform tool payloads under long context — observed repeatedly as
`request_action.parameters` emitted as a *stringified* JSON object, once with
a stray trailing `]` (`"{…}]"`). Two mechanisms:

- **Salvage, don't drop** (`agent/tools.go` `UnwrapStringifiedObject`): unwrap
  a stringified object; decode the *first complete object* with a streaming
  decoder so trailing junk doesn't kill it; re-marshal clean. A benign
  double-encoding must cost nothing; before the trailing-junk fix, every
  ticket request in a session died silently at validation.
- **Prevent, via schema shape** (`parametersSchema`): a bare
  `{"type":"object"}` with no properties is precisely what teaches a model to
  emit the field as a string blob. Enumerate real properties from the action
  catalog. (Found by the eval harness's H6 assertion — `design/10`.)

And when a payload is still bad, the error goes back to the model as a tool
result — the observed behavior is that it self-corrects on the retry. Failing
loudly *to the model* is part of the loop contract.

## 8. Ground-truth tools must exist — but expect them to be ignored

`list_actions` returns the durable action queue with an engine-computed
`expired` flag and a `now` timestamp (`agent/tools.go`), and its description
says *"use this for ground truth… never assume."* The model still skipped it
while claiming verification. Ship the tool (the guards in §3 depend on the
same read path), but never design as if instruction guarantees use.

## 9. Provenance: show what *will* act, record what *did* act

When several adapters can serve an action type, the analyst must see the
tool at both edges of the decision:

- **Before approval**: the card shows `will dispatch via <adapter>` from
  `ActionResolver.PlannedBinding`. Preview and dispatch share one selection
  function (`selectBinding`, `action/resolver.go`) so "what the card promises
  is what dispatch picks" is enforced *structurally*, not by a comment.
- **After dispatch**: `action.dispatched` records the planned adapter;
  `action.resulted` carries the adapter *actually* used, the failure reason
  (`error_detail`), and the operational reference the tool returned
  (`raw_response_ref`, e.g. the created incident number). The projection
  converges planned→actual (`aggregate/action_current.go`) — the honest-record
  rule of `design/08 §6c`.

**Field save**: the pre-approval preview exposed a silent misroute — tickets
about to dispatch to the demo fixture instead of the real system of record —
*before* the analyst approved. Provenance is not cosmetic; it catches
misconfiguration at the decision point.

## 10. Vocabulary contracts fail silently — validate them at author time

A binding whose `${parameters.X}` references an input the action descriptor
never declares is **silently never-applicable**: the resolver falls through to
a lower-priority binding and the wrong tool acts, with no error anywhere.
This shipped once (bindings authored in the tool's field vocabulary —
`short_description` — instead of the engine's canonical `summary`).
`action/validate_params.go` (`ValidateBindingParams`) now cross-checks every
required ref against the catalog's declared inputs: a hard failure in
`reckon adapter test`, a loud warning at resolver build. General rule: when
two vocabularies meet at a template seam, validate the seam mechanically —
humans and models both author the wrong side fluently.

## 11. Async outcomes need state-driven UI reconciliation

Dispatch is a durable workflow; its result events are recorded by the worker,
off the HTTP path that pushes deltas. A fixed post-approve poll window went
stale the first time a cold external call outran it — the ledger showed
DISPATCHING long after the engine recorded SUCCEEDED. The fix
(`investigationDocument.ts` `scheduleDispatchWatch`): poll **while any action
is in a transient state** (APPROVED/EXECUTING), stop when everything is
terminal, bounded as a backstop. Reconcile on *state*, never on *elapsed
time* — fixed windows encode an assumption about latency that externals will
break.

## 12. Model choice is configuration — and rarely the root cause

`agent.DefaultAnthropicModel` / the workbench `reckon.model` setting select
the model; the loop treats it as config (`agent/anthropic.go`). Worth noting:
the fabrication above happened on the *top* tier — upgrading the model would
not have fixed the poisoned context, and the deterministic guards work on any
tier. Diagnose the context and the mechanisms before blaming the model.

## 13. Know which process runs the loop

The workbench agent runs in a **sidecar** (`reckon investigate --stdio`,
spawned once and reused — `implementation/agent-sidecar.md`), not in the
backend. A behavior fix "not taking effect" was, twice, a stale process: the
backend was restarted (which never touches the sidecar), or the sidecar
predated the rebuilt binary. Discipline: after changing `agent/`, rebuild the
CLI binary and respawn the sidecar (reload the workbench window); verify with
`strings <binary> | grep <new prompt phrase>` when in doubt.

## 14. Graduate field lessons into eval assertions

Every lesson here started as a live incident. The eval harness
(`design/10`, `eval/`) is where they stop being anecdotes: the
stringified-parameters salvage traces to its H6 finding, and the
narrative-poisoning defenses of §2–§3 now graduate into assertions
(`eval/graders.go`, catalogue `v0.7`):

- **G4 — no fabricated identifiers.** Every UUID the model cites in its own
  prose must be one the engine actually produced (a tool result, the durable
  actions view, or the investigation id); a token the system never emitted is a
  fabrication, decided by set membership with no prose judgment. This is the
  eval form of §2's field crisis. `SHOULD`, not `MUST`, for one honest reason:
  the committed record does not yet capture the ids the backend injects into the
  base prompt (seed entity STIX ids), so a legitimately-quoted seed id could
  false-positive — tightening to `MUST` waits on capturing that set.
- **H7 — the footer is wired.** When the model cites an `action_id`, the
  committed record must carry the reconciliation footer (§3). This catches a
  regression that removes the correction even when the model behaved — the case
  G4 alone would pass.
- **H8 — creation claims are backed.** A turn narrating a creation must carry a
  `request_action` the backend accepted; a claim with zero tool calls is the
  phantom-action confabulation. A rejected *attempt* is H5/H6's concern, not
  H8's — the model engaged the tool, so honest failure-reporting is not
  penalized.

When a road-test finds an agent defect, the fix isn't done until the harness
would catch its regression — these three close that loop for the fabrication
class.

<!-- end of implementation/agent-reliability.md -->
