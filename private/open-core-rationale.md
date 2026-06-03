# Open-core rationale (private)

Extracted from `design/05-component-architecture.md` when the spec was sanitized for public-OSS readiness. The architectural shape of the open-core split lives in the public spec (`§13.1–§13.5`); the commercial *why* — which buyers each module converts, what conversion event drives each purchase, and the strategic commitment to *not* compete with SOAR on workflow-shaped work — lives here.

## The two paid conversion hooks

The paid distribution exists to satisfy two distinct buyers, each motivated by a different operational pain. Conflating them — bundling them as one inseparable module, or skipping one — costs revenue.

### Tenancy module — converts the MSSP/MDR

**Conversion event:** running N separate OSS installs across N client environments becomes operationally painful. The paid tenancy module consolidates them onto one multi-tenant instance, with the consolidation-lift workflow handling the data movement.

The buyer is the MSSP, not the MSSP's client. They pay per tenant or per analyst, not per client environment.

### Governance module — converts the in-house single-environment enterprise SOC

**Profile:** this buyer never wants multi-tenancy and would otherwise use the free OSS forever.

**Conversion event:** a compliance, audit, or SSO requirement that the OSS install's raw Keycloak admin console and unstructured audit export cannot satisfy. The paid governance module ships the operational surface that makes those requirements pleasant to operate: federated SSO setup, polished tenant-admin UI, signoff queues, compliance-friendly audit exports.

### Independence

Both modules are additive, both are independently licensable, and they share no dependencies that would force a customer to buy both. This is TR-26 hook 1 and TR-26 hook 2, satisfied by construction.

## No third paid conversion hook into workflow-shaped/T1-volume work

By design. The open-core commitment is to the judgment-shaped half of the SOC's work — novel investigations, hunts, response under uncertainty. The workflow-shaped half (alert triage, fixed-step enrichment, high-volume auto-containment) is SOAR's domain and remains so.

The architecture *could* let aatu's reasoning loop run at T1 volume; the product *won't*, because forcing an LLM loop onto playbook-shaped work is bad economics (LLM tokens per FP-close) and worse reliability (a directed playbook is more deterministic than an LLM deciding to investigate a known-FP class).

Coexistence with SOAR (TR-18) is not just about delegating writes — it's about respecting that workflow-shaped and judgment-shaped work want different primitives, and the two products serve different shapes of work, not different tiers of analyst.

## Why this lives in private, not the public spec

The architectural fact — "two optional modules, tenancy and governance, that layer on the OSS engine through stable interfaces" — is OSS-appropriate and stays in `design/05 §13.1–§13.5`.

The commercial fact — "who buys which module under what conversion event, what we deliberately won't sell against" — is positioning. It's the kind of context that's useful to an investor, a design partner, the founder, and the founder's AI agents working on commercial work, but it doesn't belong in an OSS spec.

The principle: every fact in the public spec should be defensible as an architectural commitment a contributor needs to understand. Buyer profiles aren't that.

## Linked

- `design/05-component-architecture.md §13` — the architectural shape this rationale's commercial framing was extracted from
- `private/pitch.md` — the user-facing positioning that builds on this rationale
- `MEMORY.md project_aatu_open_core_decisions` — the seven settled decisions, of which the "two distinct conversion hooks" framing is part