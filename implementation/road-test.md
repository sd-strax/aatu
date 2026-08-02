# reckon road test — investigate → conclude → remediate

A manual, end-to-end exercise of the v0 fixture stack through the **workbench
UI**. It follows the natural analyst loop: understand the host, drive the
hypothesis to a verdict, *then* act — because remediation lands clean only when
evidence precedes it.

Everything is in the workbench except the one step tagged **[simulate vendor]**
(an outside party replying — no UI by design in v0). It runs entirely against
the `lateral-movement-via-rdp` fixture scenario; there are no real adapters.

> Keep this in sync when a surface changes. It doubles as the "does the whole
> thing still hang together" check before a demo.

**Prereqs:** stack running on the current binary, workbench reloaded, signed in,
BYOK `ANTHROPIC_API_KEY` set. Start a **fresh** investigation so the arc is
clean.

---

## 1. Seed + investigate — this populates the analytical surfaces

**New Investigation** (`Ctrl/Cmd+Shift+I`) → type **`WIN-FILE01`** → confirm the
live hint reads *"→ investigate host WIN-FILE01"* → **Start investigation**.

Then, in the composer:

> *"Investigate WIN-FILE01 for signs of compromise — what happened on this host?
> Pull the process, logon, and network telemetry and tell me if this looks like
> lateral movement."*

**Expect:** the agent queries the fixture telemetry (RDP logons, the C2 network
flow, the detection), narrates what it found, and **records a hypothesis** —
something like *"WIN-FILE01 was accessed via RDP using a compromised service
account."* The **Hypotheses** rail now has content, and tool-result rows carry
pinnable evidence chips.

*(If it investigates but doesn't record a hypothesis, nudge: "Record your
leading hypothesis." Agent-proposed or human-authored both land in the tracker.)*

> **On activation (no button).** A fresh investigation starts as a **Draft**.
> Reasoning, hypotheses, pins, and the verdict are all allowed while it's a
> draft — so steps 1–3 work as-is. It **activates automatically** the moment you
> approve its first external action (step 4); there is no "Activate" button.
> (Conclude, step 5, requires an active investigation — which it is by then.)

## 2. Drive the hypothesis loop (the tracker's reason for existing)

On the hypothesis card, walk the ladder:

- **✓ Acknowledge** — if it's an AI-**proposed** hypothesis, this is **required
  before the agent can go further**. Human-in-the-loop is the default: the agent
  cannot run tests on, or decide, a still-`PROPOSED` hypothesis until a human
  Acknowledges it into `OPEN`. Skip it and the agent will refuse, honestly
  ("a human must Acknowledge it first"). *(To let the agent drive the whole loop
  autonomously, set the tenant dial `trust.ai_reasoning: true` — off by default.)*
- **⚡ Propose tests** → the agent records falsifiable predictions (the aside
  collapses to a one-liner).
- **⚡ Run tests** → it executes the predictions and records outcomes citing
  evidence.
- **📌 Pin** a decisive prediction's evidence (the button goes inert once pinned).
- **⚡ Decide** → it records support/refutation citing the decisive test evidence.

**Expect:** each ⚡ fires a collapsed aside; predictions live only in the
tracker; the pin shows up in **Pinned evidence**.

## 3. Verdict — grounded in the pins

**Verdict…** → the dialog shows the pin gate (you pinned evidence in step 2, so
it's satisfied) → disposition **MALICIOUS** → rationale → **Record verdict**.

**Expect:** the verdict badge appears in the header; the verdict act shows in the
chronicle (⚖ line).

## 4. Remediate — now the agent is an ally, because evidence precedes action

Everything the agent would refuse in a remediate-first run now lands clean. Ask,
one at a time or together:

> *"Isolate WIN-FILE01, block the C2 IP at the perimeter, open a ticket to
> reimage it in the IT queue, and notify #it-operations on Slack that it's
> contained and ready for reimage — ask them to schedule it, follow up in 48h."*

**Expect** a sequence of approval cards, each a decision-grade preview:

- `host.isolate` → target WIN-FILE01, reversibility stated
- `ioc.block` → the C2 indicator
- `ticket.create` → target the **IT queue** (WIN-FILE01 rides in evidence, not
  targets), manual approval
- `notify.slack` → **pre-send preview** ("Approve · Send") — the message text
  *is* the approval surface

Approve them. **Expect:** approving the first one **activates** the investigation
(the Draft badge flips to Active); dispatches succeed; the ticket returns an id;
the notify opens an **External work** card (`#it-operations`, `awaiting_reply`,
48h clock). Each act lands as a one-liner in the chronicle in causal order, and
each action appears in the new **Actions** ledger on the rail with its status
badge (`SUCCEEDED`, tier, target) — where it stays after completion, unlike the
"Needs your approval" interrupt.

### 4a. Comms round-trip

**[simulate vendor]** IT replies. Grab the thread id, then post an inbound reply:

```bash
INV=<the UUID under the title>
curl -s http://localhost:8080/api/investigations/$INV/comms \
  -H "Authorization: Bearer $TOKEN" | jq -r '.threads[] | "\(.thread_id)  \(.target)  \(.status)"'

curl -s http://localhost:8080/api/comms/inbound \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"thread_id":"<THREAD_ID>","author":"Mike Torres","body":"Reimage scheduled tomorrow 9am."}'
```

**Expect:** the card flips to `replied` (green) with an unacked cue →
**Acknowledge** → try **Follow up…** (goes through request → preview →
Approve · Send, extending the *same* thread) → **Mark done** → `closed`.

## 5. Conclude — both gates fire meaningfully

**Conclude…** → the helper shows the verdict-of-record it consumes, and if you
left a comms thread open, the ⚠ comms conclude-gate warning. Close cleanly (or
leave a thread open to see the warning, then Mark done, then conclude).

**Expect:** status → CONCLUDED; if auto-export is on, the bundle fires.

---

## Lenses — check these anytime (they're views, not steps)

- **Chronicle:** read the document top-to-bottom — investigate → hypothesis acts
  → pins → verdict → the four remediations → comms → conclude, all in causal
  order. This is the "case file a colleague could read at handoff" test.
- **Evidence card:** click any cited ref (a `WIN-FILE01` chip, a graph node, an
  events-strip dot) → a **rendered card** opens beside the document: human title,
  a provenance banner, structured fields, and cross-investigation memory (who
  else has cited this entity). Raw JSON is one click away ("Open raw JSON tab")
  for jq. One reused panel — clicking another ref updates it in place.
- **Evidence graph** (header/rail fold): the **two-layer structure** —
  interpretation-layer STIX objects (reasoning nodes + SCOs) on the left,
  telemetry (OCSF) on the right, edges pointing from a produced object to the
  evidence it cites. A reasoning object that reaches no evidence is flagged
  **ungrounded** (the summary counts them). This is the structural lens; the
  chronicle is the chronological one — they don't duplicate each other.
- **Actions ledger** (rail): every action on the investigation with its status,
  newest first — the durable record the chronicle can't be at a glance.
- **Event-time strip:** the two-clocks view — the decisive fact is a ~7-second
  gap between the RDP logons; check it's visible in *event* time, not learn time.
- **Enablement form:** find the `asset_criticality` gap hint → enable → apply →
  the capability surface updates **without a restart**; confirm your comments
  survived in `~/.reckon/capability/lateral-movement.yaml`.
- **Markdown export:** the Export button → live `export.md`; it should read as a
  coherent case, pins/hypotheses/actions/comms all present.

---

## Appendix — the dev token (only for the step-4a curl)

```bash
TOKEN=$(curl -s http://localhost:8543/realms/reckon/protocol/openid-connect/token \
  -d grant_type=password -d client_id=reckon \
  -d username=reckon-admin -d password=reckon | jq -r .access_token)
```

Short-lived — re-run on a 401. If it fails outright, run `./bin/reckon dev-auth`
once first to provision the local principal and enable the direct-access grant
(dev/CI only).

**As you go, note per surface:** did it work, did it read right, and did anything
need a curl that should have had a UI. The difference from a remediate-first run:
the agent stops fighting you, because step 4 rests on steps 1–3.
