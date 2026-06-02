# aatu — Cursor for SOC analysts

A latency-obsessed, keyboard-driven investigation surface for SOC analysts doing real investigative work — threat hunters, IR responders, the T2/T3 cases where playbooks aren't enough. Sits on a neutral cross-vendor context fabric with graduated, human-controlled AI autonomy. Open-core, self-hostable, coexists with the customer's existing SIEM/SOAR rather than replacing them.

## The job we're built for

Tier 2/3 investigation work — novel cases, multi-source pivoting, response under uncertainty — is **judgment-shaped**. The analyst is testing hunches, ruling things out, joining facts across five vendor consoles, deciding what to trust. No playbook captures it. Today's tools force the analyst to be the human translation layer between dashboards. That's where the time goes, where the institutional knowledge dies in Slack threads, and where mistakes hide.

## The product

aatu holds the case, the timeline, the evidence graph, and the AI reasoning trace as one persistent canvas in VS Code (primary) and CLI (secondary). The analyst opens a *seed* — an alert, an entity, a hypothesis, a case from their CM. The AI agent runs a capability-driven loop, pulling context from EDR/SIEM/IdP/TI/CM through a transport-neutral fabric (MCP, native vendor APIs, custom adapters). Every AI claim is evidence-linked. Every state-changing action goes through a human-controlled authorization gate. Every concluded investigation produces a structured reasoning trace that improves the next one.

## How aatu differs from SOAR

| SOAR | aatu |
|---|---|
| Workflow-shaped work | Judgment-shaped work |
| Steps knowable in advance | Steps discovered along the way |
| High-volume, repetitive | Low-volume, novel |
| Playbook as code | Investigation as reasoning trace |
| Optimizes throughput | Optimizes depth |

**Where SOAR encodes workflow-shaped work, aatu supports judgment-shaped work.** The two coexist along this axis, not along analyst tiers. SOAR is the right tool when the steps are knowable in advance (alert triage, fixed-step enrichment, auto-containment). aatu is the right tool when they aren't (the case SOAR's playbook hit "I don't know what to do here").

aatu *could* technically run its reasoning loop at T1 alert-triage volume. It deliberately won't — forcing an LLM loop onto workflow-shaped work is bad economics and worse reliability. An analyst's title (T2, T3, hunter) doesn't pick the tool. The shape of the case in front of them does.

## How aatu coexists with what's already there

aatu sits *above* the customer's SIEM/EDR/SOAR/CM, not in place of them.

- **Reads** from the customer's existing platforms via the capability layer. No data migration, no telemetry centralization — federation, not ingestion.
- **Calls** existing SOAR playbooks when one already encodes the response the analyst wants (Tines, Torq, Splunk SOAR — any orchestrator via the `SOAR_PLAYBOOK` adapter class). Or dispatches direct to vendor APIs when that's the right route. Analyst picks per action.
- **Audit-traces** every action from the evidence byte that justified it to the human who approved it to the system that executed it.

## How to start

- **OSS — fully capable, single environment.** Engine + all connectors + reasoning loop, open and free. Bundled Postgres + Temporal + Keycloak. Afternoon install. No procurement. No paywalled connectors, ever.
- **Paid — multi-tenant operation OR governance (or both).** Two independently licensable additive modules on the same Go binary. Runs **self-hosted on customer infra** or **aatu-hosted**, same Terraform either way. The line between OSS and paid is *operation and governance*, never investigative capability.

## Who it's for

- **In-house SOC threat hunters and IR responders** — the analysts whose work doesn't fit a playbook.
- **MSSP/MDR analysts** running heterogeneous client stacks. They adopt OSS *per client* (the free single-tenant install), and convert to paid when running N instances becomes operationally painful.
- **Security teams** that have to defend a decision after the fact. Every action traces to its evidence, its principal, and the model that proposed it.

## What it deliberately is not

- **Not a full-autonomy autopilot.** Human-in-the-loop is the design center, not a temporary limitation.
- **Not a telemetry lake.** It federates; it doesn't centralize or own the customer's data.
- **Not a response engine.** It delegates writes to existing SOAR/case management when one fits; it doesn't try to be the playbook layer.
- **Not a SIEM replacement.** It reads from the customer's SIEM; it doesn't compete with it.
- **Not a SOAR replacement.** Workflow-shaped work stays with SOAR. aatu picks up where playbooks stop being the right answer.

## The bet

Defensibility comes from three places the data-gravity incumbents (Sentinel, Splunk, CrowdStrike) structurally cannot match: **neutrality** (vendor-agnostic by construction, value rises with every source federated), **a single canvas for judgment-shaped work** (versus nine browser tabs and a Slack thread), and **capturing the institutional reasoning trace** that today disappears the moment the case closes.

---

*Investigation environment for the work playbooks can't encode. Open-core. Self-hostable. Coexists with what you've already got.*
