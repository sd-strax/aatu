# reckon demo — the Northwind walkthrough

A narrative demo of the full reckon loop on the bundled demo world: an
AI-native investigation that goes from an alert to a grounded verdict to a
reversible action, and then **compounds** — the concluded case teaches the
knowledge corpus, so the next investigation starts smarter.

Where [`road-test.md`](road-test.md) is the "does the whole thing still hang
together" checklist, this is the **story** you tell an audience. It runs against
the same `lateral-movement-via-rdp` fixtures, now seeded through `reckon demo
seed` rather than baked into `init`.

The fictional org is **Northwind**, a mid-size company whose SOC runs reckon.
Everything below is fixtures — no real tenant, no real adapters.

---

## 0. One-time setup (before the audience arrives)

```
reckon init                 # a fixture-free real install
reckon start                # brings up the stack (first run downloads deps)
reckon dev-auth             # a local login (the shipped realm has none)
reckon demo seed            # populate the demo world — refuses if not virgin
reckon stop && reckon start # restart so the fixture capabilities activate
```

`reckon demo seed` does two things at once:

- **Loads Northwind's institutional knowledge** into the corpus — three SOPs
  (RDP-containment, credential-theft triage, host-isolation) and **two prior
  concluded cases** (an RDP pivot on `FINANCE-07`, LSASS dumping on
  `WORKSTATION-22`). This is the history the compounding loop draws on.
- **Wires the fixture scenario** so the agent has telemetry to query.

Then in the **workbench**: reload, sign in, set your BYOK `ANTHROPIC_API_KEY`.
The knowledge is now consultable and the fixtures are live.

> If you seeded onto a dirty install it will refuse and tell you the counts —
> run `reckon demo reset` first (it wipes everything back to a clean install),
> then re-seed.

---

## Act 1 — Investigate (the agent does the legwork)

An alert fires: an interactive RDP logon into **`WIN-FILE01`**, a file server,
from an account with no reason to be there. Start a **New Investigation** →
seed `WIN-FILE01` → in the composer:

> *"Investigate WIN-FILE01 for signs of compromise. Pull the process, logon, and
> network telemetry and tell me if this looks like lateral movement."*

The agent queries the fixture telemetry, assembles the host timeline (the RDP
logon, post-logon discovery, the C2 beacon) and lays out what it found — the
analytical surfaces (timeline, entities, evidence) populate as it works.

**The compounding payoff, first half.** As the investigation takes shape, the
**knowledge rail** surfaces — with relevance scores and bands — Northwind's
*"Lateral Movement via RDP — Containment"* SOP **and the prior `FINANCE-07`
case**, flagged as a near-match. The analyst decides what the AI reasons over:
tick both to include them. The next turn is now grounded in Northwind's own
playbook and its own history. *(Nothing was force-fed — the retriever proposes,
the analyst disposes. That's the injection dial.)*

## Act 2 — Decide (grounded in pins)

Drive the hypothesis to a verdict the way [`road-test.md` §2–3](road-test.md)
lays out: the agent proposes *"stolen valid account used for hands-on-keyboard
lateral movement (T1021.001)"*, the analyst acknowledges it, evidence gets
pinned, and the verdict of record lands as **true-positive** — grounded in the
pins, not vibes.

## Act 3 — Act (evidence precedes action)

Now, and only now, remediate. Request **host isolation** on `WIN-FILE01`. Watch
the authorization chain: Gate 2 evaluates the action, the trust tier is set by
blast radius, a human approves, the action dispatches through the (fixture)
write adapter, and the result comes back honestly. Isolation is reversible —
show the reversal if you want to make the "we never claim an undo we can't
verify" point.

## Act 4 — Conclude and compound (the whole reason for the demo)

Conclude the investigation with its verdict. Two things happen, both client-side
on the BYOK key — **the backend never holds a model key**:

1. **A knowledge summary is written** — a deterministic structured baseline
   (seed, techniques, actions, outcome) enriched by a model narrative drawn from
   the investigation's own conversation. This is what makes the case
   *recallable* later.

2. **A candidate SOP is drafted.** The model generalizes across *this* case and
   the `FINANCE-07` case it consulted — not a retelling of one investigation,
   but a reusable procedure — and opens it as an **editable markdown draft** with
   a prompt: **Add to SOP library** or **Discard**. The analyst reviews it (edits
   if they like), and accepts. *(If an existing SOP already covered it, the model
   says so and proposes nothing — no duplicate clutter.)*

**Close the loop out loud:** the corpus now holds a new SOP that *this*
investigation produced. Start another investigation and its knowledge rail will
surface that very SOP. Each concluded case makes the next one better — with a
human deciding, every time, both what gets acted on and what gets learned.

---

## Reset (graduate to real work)

When the demo's done:

```
reckon stop
reckon demo reset           # wipes investigations, knowledge, fixtures
reckon start                # a clean, real install
```

`reset` removes the demo databases (they re-initialize empty on next boot),
Temporal's store, and the seeded fixtures — Keycloak (your login) survives. The
same install an analyst test-drove is now an empty, real one, ready for their
own adapters and their own cases.

---

## The one-sentence version

reckon runs the investigation loop with the analyst in command of every
consequential decision — and every concluded case feeds the next, so the SOC's
knowledge compounds instead of walking out the door with the analyst who built
it.
