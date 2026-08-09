# Agent Behavior & Prompt Management — Design Note

## 0. Framing

The investigation agent (`05 §2` (commitment 7), `05 §3.4`) is driven by a system prompt plus a set of tools. As
soon as the loop met a real analyst, a pattern emerged: the agent misbehaved in small ways —
hallucinating an out-of-product step, summarizing when asked for raw data, offering a
methodologically out-of-order next step and then conceding instantly when challenged. Each is
individually a "prompting issue." Taken together they raise the actual design question this note
owns:

> **When the agent does the wrong thing, what layer should own the fix — the engine, or the prompt —
> and how do we manage the prompt as an artifact that will take many iterations to get right?**

This note is a **design discipline**, not a hard contract. It defines how we decide where a behavior
is enforced, how the system prompt is structured and versioned as it grows, and the boundary between
*product reasoning* (how reckon thinks) and *tenant behavior* (how a given SOC operates). The loop
mechanics, the authorization mechanisms, and SOP retrieval are specified elsewhere and are
authoritative; this note builds on them.

Field evidence for this discipline — what actually broke against a live stack and the deterministic
mechanisms that fixed it (narrative poisoning, ground-truth guards, the analyst context reset) —
lives in `implementation/agent-reliability.md`. Read the two together: this note decides *where a
fix belongs*; that one records *what the field taught us*.

| Owned here (`09`) | Owned elsewhere (authoritative) |
|---|---|
| The mechanism-vs-prompt layer decision (`§2`) | The AI-delegate write protections, Gate 2, baseline DENY (`04`) |
| System-prompt structure, versioning, evaluation (`§4`, `§6`) | The agent loop, tool assembly, turn commit (`05 §3.4`) |
| The product-reasoning vs tenant-behavior boundary (`§5`) | The SOP corpus + retrieval (`06`); CEL policy (`04 §4`) |
| The containment→hypothesis soft-mechanism proposal (`§3`) | The `x-hypothesis`/`x-action` primitives + evidence edges (`01`) |

### Out of scope

- **The loop itself.** Model↔tool rounds, transcript commit, the two-token seam — `05 §3.4`, `08`.
- **The hard authorization mechanisms.** AI-cannot-approve, blast-radius escalator, baseline DENY are
  settled in `04` and are the canonical examples of `§2`'s "mechanism" side, not re-litigated here.
- **Specific prompt text.** This note governs how prompts are *managed*, not their wording. The living
  text is a code artifact (`agent/prompt.go` today), reviewed like code.
- **Model selection / inference config.** Provider, model id, token budgets are surface config
  (`05 §3.4`, `agent/`), independent of behavior management.

---

## 1. The problem: a security product cannot rest on persuasion

A prompt is a *soft* control. The model may follow it, or may be argued out of it — as observed when
the agent abandoned its own stated methodology in a single conforming sentence ("you're absolutely
right"). For a product that reasons over security telemetry and proposes containment, any invariant
whose violation could harm a tenant must not depend on how persuasively a paragraph was phrased.

The corrective is not "write better prompts." It is to **decide, per behavior, which layer owns it**,
and to reserve prompts for the reasoning texture that sits on top of hard guarantees.

## 2. The core discipline: mechanism vs. prompt

For every behavior we want, ask one question first:

> **Could a wrong answer here harm a tenant, or be adversarially exploited?**

- **Yes → mechanism.** Enforce it in the engine (command guard, projection invariant, authorization
  gate) where the model cannot override it. The model's cooperation is not required for the guarantee
  to hold.
- **No → prompt.** It is methodology, tone, or output style. A prompt convention is the right,
  cheap tool; a lapse is a quality issue, not a safety breach.

This is the same principle the domain already applies to authorization — *the AI is a delegate, never
a principal* is a mechanism (`delegate_kind` derived from the token, Gate 2 baseline DENY), never a
prompt request. `§2` generalizes that stance to all agent behavior.

### 2.1 Triage of observed behaviors

| Behavior | Layer | Rationale |
|---|---|---|
| AI approves/concludes/archives | **Mechanism** | Correctness-critical, adversarial. Enforced at the aggregate allowlist + Gate 2 (`04`). |
| Fabricating an action's status | **Mechanism + prompt** | Truth comes from the event log via `list_actions`; the prompt directs the model to consult it rather than recall. |
| Action requested with no `evidence_refs` | **Mechanism** (`§3` update) | Was prompt-only; a capable model omitted grounding 1-in-3 under load (`10 §3`, G1). `BuildRequestCommand` now rejects it; schema marks `evidence_refs` required. Reversals exempt. |
| Containment proposed with no validated hypothesis | **Candidate mechanism** (`§3`) | Methodology today, but the domain has the hooks to make it an auditable signal. |
| Directing the analyst to an external console | **Prompt** | Factual framing of how approval/execution works in-product. No correctness stake once stated. |
| Summarizing when raw output was requested | **Prompt** | Instruction-following/style. |
| Sycophancy / caving without evidence | **Prompt** | Tone — but a symptom worth naming explicitly (`§4.1`). |

### 2.2 The rule for new behavioral bugs

When a behavioral defect is found, its first triage is **layer, not wording**. A defect routed to
"prompt" that actually protects a tenant is a latent incident. A defect routed to "mechanism" that is
mere style is over-engineering. The table above is the worked precedent; extend it as new cases
arrive.

## 3. Worked example — promoting "hypothesis-first" from convention to signal

"Work hypothesis-first" is a prompt convention today (`agent/prompt.go`). The agent treating it as
optional — offering containment as a peer alternative to forming a hypothesis — is the archetype of a
methodology that *could* be a soft mechanism, because the domain model already carries the evidence:

- An `x-action` request carries `evidence_refs` (`01`, `08 §2`).
- The reasoning thread knows whether any `x-hypothesis` exists for the investigation (`01`, the
  reasoning projection).

That makes it mechanically observable whether a containment request is grounded in validated
reasoning. Options, in ascending strictness — **this note proposes the direction, not the setting**:

1. **Annotate (audit-only).** Record on the `action.requested` path a derived flag —
   *action requested with no supporting hypothesis* — visible in the audit view. No behavior change;
   pure observability. The honest floor.
2. **Warn.** Surface the flag back to the agent as a non-blocking tool result, nudging it to justify
   or reconsider — enforced by the engine, not the prompt.
3. **Require override.** Treat an ungrounded containment request as needing an explicit analyst
   acknowledgment before it can be approved, on top of Gate 2.

Strictness should be a *config*, consistent with the trust-dial posture already parked for hypothesis
adjudication (`01`, open questions): a tenant trying the product may want (1); a mature tenant may
adopt (2) or (3). The mechanism is the same; the dial is tenant policy. This keeps methodology
enforcement **auditable and adjustable** rather than resting on the model's disposition, and it is
deliberately decoupled from the authorization tier (blast radius still drives the tier; grounding is a
separate axis). Left as an open design question (`§7`) pending field feedback.

> **Update — the evidence-refs floor is now a mechanism.** The dial above concerns
> *hypothesis existence* (is there a validated `x-hypothesis`?). Its weakest form —
> does the action cite **any** grounding evidence at all — has been graduated to a
> hard mechanism ahead of the dial, because the eval caught the failure it guards:
> a live opus run requested `account.disable` with no `evidence_refs` in 1 of 3
> trials (`design/10 §3`, G1). `action.BuildRequestCommand` now rejects a forward
> action with empty `evidence_refs`, and `request_action`'s tool schema marks the
> field required (`minItems: 1`) so the model rarely trips the reject. Reversals
> are exempt (grounded by `reversal_of_ref`). This is the `§2.2` rule applied: a
> trust-critical property that a capable model violated under load moves off
> persuasion. The *hypothesis-existence* dial (options 1–3) remains open — a
> present-but-thin grounding is a stricter, still-adjustable question.

## 4. The system prompt as a managed artifact

### 4.1 Current state

The entire system prompt is assembled in one function (`agent/prompt.go`) as a single string:
identity, reasoning conventions, authority boundaries, and the live investigation context,
concatenated at session start. It is git-versioned and touched by unit tests — prompts are code,
reviewed and diffable, which is the correct baseline. Its limits, in order of what will bite first:

1. **Iteration requires a rebuild.** Every wording change is a binary rebuild + redeploy.
2. **No regression safety.** Fixing one behavior can silently break another; nothing catches it.
3. **No attribution.** When behavior shifts, there is no recorded link from a transcript to the
   prompt version that produced it.
4. **No structure for growth.** A single blob will accrete per-verb guidance, few-shot examples, and
   per-scenario nuance until it is unmaintainable.

Sycophancy (`§2.1`) is worth an explicit prompt provision: the agent must not concede a point without
evidence, and its suggested next steps must respect the stated methodology (never offer containment
ahead of a validated hypothesis) — the prompt-side complement to `§3`'s mechanism.

### 4.2 Maturity curve (forward-looking; not yet built)

Cheapest-first, each step independently valuable:

- **Decompose the blob** into named sections (identity / reasoning discipline / authority boundaries /
  output contract / context injection). Even in Go, labeled pieces make diffs reviewable and let
  sections change independently.
- **Externalize to embedded text** (`//go:embed`). Prompts become editable, diffable prose shipped
  with the binary — separated from code, still versioned, and a step toward later hot-reload.
- **Version + attribute.** Stamp a prompt-version identifier into each turn's reasoning-thread
  interpretation (the transcript is already recorded; add the prompt id). Behavior becomes traceable
  to a prompt version — the prerequisite for iterating with confidence.
- **Eval harness** (`§6`). The real unlock.

## 5. Product reasoning vs. tenant behavior

reckon already has a channel for tenant-specific behavior that is **not** the base prompt: the SOP
corpus (`06`, `recall_sops`). This yields a separation to protect:

- **Base system prompt = product artifact.** *How reckon reasons* — hypothesis-first, coverage
  honesty, authority boundaries, output discipline. Ships with the engine, versioned in-repo,
  evaluated (`§6`). Tenants do not edit it.
- **SOPs = tenant knowledge, as data.** *How this SOC handles a situation.* Retrieved and injected at
  reasoning time; iterated by the tenant with no rebuild; already first-class (`06`).
- **Policies = tenant guardrails, as config.** Gate 2 CEL (`04 §4`) — the hard tenant rules.

Most iteration a tenant wants happens in SOPs (data) and policies (config); most iteration the product
wants happens in the base prompt (code + evals). Keeping tenant nuance out of the base prompt prevents
coupling product behavior to any one deployment, and is consistent with the open-core boundary: the
OSS engine ships the base prompt and has no awareness of paid modules (`CLAUDE.md`, "Open core").

**Open boundary decision.** The loop is client-side (BYOK, `05 §2` commitment 7), so the base prompt is assembled
client-side today. As prompt management matures, whether the base reasoning prompt stays client-shipped
(versioned with each surface) or moves server-provided (versioned once, tenant-agnostic, identical
across CLI and VS Code) is a deliberate fork — recorded in `§7`. The current lean is server-provided,
so all surfaces reason identically, but this is not yet decided.

## 6. The evaluation harness

Prompt iteration without evaluation is change without a safety net — precisely the regime that makes
prompts feel like guesswork. The harness is the highest-leverage investment for the exact reason
prompts take many iterations.

Shape (forward-looking):

- **Behavioral assertions over transcripts**, not golden-string matches. Examples: *does not
  `request_action` before an `x-hypothesis` exists*; *cites refs in every evaluation*; *honors a
  raw-data request*; *does not concede a challenged claim without evidence*; *classifies coverage
  honestly on an unavailable source*.
- **An offline eval mode** that runs the **real** model against scenario fixtures and scores the
  resulting transcript against the assertions. The existing test scaffolding (`scriptedLLM` +
  `fakeBackend`, `agent/`) covers deterministic loop mechanics; the new piece is a graded run against
  a live model, kept out of the `-short` path.
- **Tied to prompt versioning** (`§4.2`): every eval run records the prompt version it scored, so a
  regression is attributable and a change is defensible.

This makes prompt iteration a graded loop rather than vibes-and-regressions. It is a distinct piece of
work, appropriately its own phase — designed in `10-eval-harness.md` (assertion catalogue, scoring
model, run attribution, harness architecture).

## 7. Open questions / deferred to v1+

- **Grounding-strictness dial (`§3`).** Whether ungrounded containment is annotated, warned, or
  gated, and whether the setting is tenant policy alongside the hypothesis-adjudication dial (`01`).
  Ships at the audit-only floor if adopted at all; higher strictness pending field feedback.
- **Base-prompt location (`§5`).** Client-shipped vs. server-provided. Current lean: server-provided;
  undecided.
- **Prompt externalization + versioning (`§4.2`).** Structure and the version-attribution mechanism
  are agreed in shape, not yet designed in detail.
- **Eval harness scope (`§6`).** ~~The assertion catalogue and scoring model are their own design
  pass.~~ Designed: `10-eval-harness.md`. Its own open questions (judge design, flakiness/cost
  budgets, assertion versioning) live in `10 §9`.

---

*End of design note. Builds on `01-domain-model.md` (primitives, evidence edges), `04-action-authorization.md`
(the canonical mechanism examples), `05-component-architecture.md §2` (commitment 7) and `§3.4` (the agent loop), and
`06-knowledge-service.md` (SOPs as the tenant-behavior channel). This note governs how agent behavior
is managed; it defines no new primitive.*
