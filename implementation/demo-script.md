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
# --- configure embeddings (see below) before starting ---
reckon start                # brings up the stack (first run downloads deps)
reckon dev-auth             # a local login (the shipped realm has none)
reckon demo seed            # populate the demo world — refuses if not virgin
reckon stop && reckon start # restart so the fixture capabilities activate
```

**Configure vector recall first.** The knowledge rail's relevance scores,
similarity bands, and the "have we seen this before?" case recall are all
cosine-similarity over embeddings — the full product, not a keyword fallback.
Add an embeddings backend to your config (`~/.reckon/config.yaml`) before the
first `reckon start`:

```yaml
knowledge:
  embeddings:
    base_url: https://api.openai.com/v1
    model: text-embedding-3-small
    api_key: env://OPENAI_API_KEY        # a secret REFERENCE, never a literal
```

`api_key` is a secret *reference*, never a literal. For a demo, `env://` is the
least ceremony — `export OPENAI_API_KEY=sk-…` in the shell that runs the stack;
for a longer-lived install use `keychain://<service>/<name>` instead. Either way
this is a *separate* key from your Anthropic BYOK key (the reasoning LLM has no
embeddings endpoint). `reckon demo seed` **refuses without an embeddings
backend** — the demo can never fall into the keyword-only path, because the prior
cases are embedded at seed time so similarity recall can rank them.

`reckon demo seed` then does two things:

- **Seeds two prior concluded cases** into the corpus — an RDP pivot on
  `FINANCE-07` and LSASS dumping on `WORKSTATION-22` — embedded at write time.
  This is the history the compounding loop recalls by similarity.
- **Wires the fixture scenario** (telemetry to query) and **stages the SOP docs
  to disk** (`~/.reckon/sops/`) — it prints the path. The SOPs are *not* loaded
  into the corpus; you import one **live** in Act 1, as part of the story.

Then in the **workbench**: reload, sign in, set your BYOK `ANTHROPIC_API_KEY`.
The fixtures are live and the prior cases are consultable.

> If you seeded onto a dirty install it will refuse and tell you the counts —
> run `reckon demo reset` first (it wipes everything back to a clean install),
> then re-seed.

---

## Act 1 — Teach reckon the playbook (a live import)

Open the door with the knowledge, not the alert. Northwind has a written runbook
for exactly this class of incident — **`~/.reckon/sops/lateral-movement-rdp-containment.md`**
(the path `demo seed` printed). Open it and walk the audience through it: it's a
plain markdown SOP with YAML frontmatter — a title, an author, tags, a
recommendation. Ordinary institutional knowledge, the kind every SOC has sitting
in a wiki.

Now bring it into reckon **live**. In the workbench, run **Import SOPs…**, pick
that file. It lands in the corpus in one motion — no library to manage, no
ceremony. *This is the import capability, shown, not seeded behind the curtain.*
Hold the thought: in a minute you'll see the SOP you just imported surface on its
own, exactly when it's relevant.

## Act 2 — Investigate (the agent does the legwork)

An alert fires: an interactive RDP logon into **`WIN-FILE01`**, a file server,
from an account with no reason to be there. Start a **New Investigation** →
seed `WIN-FILE01` → in the composer:

> *"Investigate WIN-FILE01 for signs of compromise. Pull the process, logon, and
> network telemetry and tell me if this looks like lateral movement."*

The agent queries the fixture telemetry, assembles the host timeline (the RDP
logon, post-logon discovery, the C2 beacon) and lays out what it found — the
analytical surfaces (timeline, entities, evidence) populate as it works.

**The compounding payoff, first half.** As the investigation takes shape, the
**knowledge rail** surfaces — with relevance scores and similarity bands — the
*"Lateral Movement via RDP — Containment"* SOP **you imported a minute ago** and
the prior `FINANCE-07` case, flagged as a near-match. Nobody wired them to this
investigation; the retriever found them by meaning. The analyst decides what the
AI reasons over: tick both to include them. The next turn is now grounded in
Northwind's own playbook and its own history. *(Nothing was force-fed — the
retriever proposes, the analyst disposes. That's the injection dial. And the
scores and bands are the vector backend at work — the reason we configured
embeddings up front.)*

## Act 3 — Decide (grounded in pins)

Drive the hypothesis to a verdict the way [`road-test.md` §2–3](road-test.md)
lays out: the agent proposes *"stolen valid account used for hands-on-keyboard
lateral movement (T1021.001)"*, the analyst acknowledges it, evidence gets
pinned, and the verdict of record lands as **true-positive** — grounded in the
pins, not vibes.

## Act 4 — Act (evidence precedes action)

Now, and only now, remediate. Request **host isolation** on `WIN-FILE01`. Watch
the authorization chain: Gate 2 evaluates the action, the trust tier is set by
blast radius, a human approves, the action dispatches through the (fixture)
write adapter, and the result comes back honestly. Isolation is reversible —
show the reversal if you want to make the "we never claim an undo we can't
verify" point.

## Act 5 — Conclude and compound (the whole reason for the demo)

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
