# Adapter Plugin Model — Spec

## 0. Framing

This spec defines how adapters — read (`03`) and write (`08`) — are **packaged, discovered,
described, and enabled** as out-of-process plugins. The adapter *contracts* are already specified
and authoritative elsewhere: `03 §5.3` (the `Adapter` interface, five classes), `03 §6.2` (error
taxonomy), `08 §5` (the `WriteAdapter` operation contract, idempotency). This spec owns the layer
beneath them: the process model that lets an adapter be a separately built, separately versioned,
separately distributed artifact, and the explicit-enablement model that governs what an installed
adapter is allowed to contribute to a tenant's catalogs.

The one-sentence summary of the whole design: **an adapter is its own process; a static manifest
says it exists; the RPC handshake says what it can do; and nothing it can do is live until tenant
config names it.**

| Owned here (`11`) | Owned elsewhere (authoritative) |
|---|---|
| The plugin process model and JSON-RPC/stdio transport (elevates `03 §5.4`'s deferral) | The `Adapter` / `WriteAdapter` semantic contracts (`03 §5.3`, `08 §5`) |
| The local install layout and manifest format | Distribution: packaging, indexes, signing, install verification (`12-adapter-distribution.md`) |
| The `initialize`/`describe`/`configure` handshake and protocol versioning | Descriptor semantics: `CapabilityDescriptor` (`03 §5.1`), `ActionDescriptor` (`08 §3`) |
| Adapter instance configuration: the config schema, the `x-secret` rule, delivery (`§4.3`) | Credential storage and resolution (`05 §10.2`) |
| The enablement model (adapter gate, per-op allowlist, read/write asymmetry, named instances) | Binding resolution and health (`03 §3`, `08 §4`), Gate 2 and tiers (`04`) |
| Fail-closed rules on install, upgrade, and drift | Verb/action-type registration flow (`05 §6.4`) |

### Out of scope

- **What an adapter does.** Operation semantics, OCSF shaping, normalization, `WriteResult`
  classification — all unchanged and owned by `03`/`08`. This spec moves adapters out of process;
  it does not touch what crosses the boundary.
- **Authorization.** Enablement (this spec) is surface control — it decides what appears in the
  catalogs. Whether a given request may proceed is Gate 2, trust tiers, and the blast-radius
  escalator (`04`), evaluated per request. Nothing here is a substitute for that, and nothing here
  duplicates it.
- **Distribution and trust of adapter binaries.** Packaging, the index model, signing, digest
  verification, upgrade, and revocation are `12-adapter-distribution.md`. This spec consumes an
  installed, verified adapter directory and is agnostic about how it got there (index install,
  mirror, `git clone && make`).
- **Credential resolution.** Adapters receive a `credentials_ref`; resolution is the uniform
  scheme in `05 §10.2`.

---

## 1. Why out-of-process is the plugin boundary

`03 §5.3` registers in-tree adapters from package `init` and defers out-of-process adapters to "the
transport-neutral path, see §5.4." This spec makes out-of-process the **primary** extension shape:
the plugin boundary is the process boundary.

The technical argument: Go has no viable in-process plugin story. `plugin` is platform-limited and
version-locked to the exact toolchain; reflection-based discovery doesn't exist. Any in-process
extension is a fork-and-recompile.

The architectural argument is stronger and mirrors the module seam (`implementation/module-layout.md`):
an out-of-process adapter is **separately versioned, separately licensed, and separately
distributed by construction**. An adapter can be written in any language, released on its own
cadence, and shipped by anyone — a community contributor, a vendor, an internal team — without
linking against or recompiling the engine. The engine's contract surface (this protocol plus the
`03`/`08` semantic contracts) is the whole coupling. This is the proven shape of LSP servers and
Terraform providers, and it is what makes the adapter ecosystem independent of the engine's
repository.

In-tree adapters do not disappear: the `FIXTURE` adapter stays compiled-in (it is test/replay
infrastructure, not an integration), and nothing forbids future in-tree adapters where it makes
sense. But the extension story told to the world is: **write a process, speak the protocol**.

### 1.1 Relationship to MCP

MCP is one of the five adapter *classes* (`03 §5.4`) — a transport reckon consumes. The plugin
protocol defined here is deliberately MCP-adjacent (JSON-RPC over stdio, an initialize handshake,
capability listing) but it is **not** MCP, because a generic MCP server does not promise what the
engine's normalizer and dispatch layers depend on: OCSF-shaped payloads, the `03 §6.2` error
taxonomy, health reporting, and idempotent write dispatch. The reckon plugin protocol is a narrow,
reckon-shaped contract that happens to ride the same plumbing. Wrapping an existing MCP server in a
reckon adapter is intended to be a thin, mostly mechanical bridge — that is the MCP class's job.

---

## 2. Process model and transport

One adapter = one executable, spawned and supervised by the backend, speaking **JSON-RPC 2.0 over
stdio**. stdio is chosen over a socket for v0 because it gives parent-child lifetime coupling for
free (adapter dies with the backend, no orphan listeners, no port management) and is the least
common denominator across languages. A socket transport for adapters that outlive the backend or
run remotely is a v1+ extension slot, not a v0 concern; `05 §6.1`'s cloud-side worker deployment
reuses the same protocol over whatever carrier that fleet uses.

Lifecycle:

1. **Spawn** — the backend launches the executable named by the manifest (`§3`), with no
   credentials in the environment (`05 §10.2`: credentials resolve per-invocation, not per-process).
2. **Handshake** — `initialize` (`§4.1`) negotiates protocol version, `describe` (`§4.2`) returns
   the adapter's self-description, and `configure` (`§4.3`) delivers the instance's validated
   config as the final step. A failed or timed-out handshake — including a rejected `configure` —
   marks the adapter `UNHEALTHY`; its contributions surface as unavailable in the catalogs
   (`03 §6.3`) and nothing else happens.
3. **Serve** — `invoke` / `dispatch` / `health` calls per the `03`/`08` contracts, mapped 1:1 onto
   JSON-RPC methods. Concurrency is per-adapter declared in the handshake (default: serial), so a
   single-threaded script is a valid adapter.
4. **Supervision** — the backend restarts a crashed adapter under the same budgeted-restart policy
   the supervisor applies to its own components; restart exhaustion marks it `UNHEALTHY` rather
   than escalating to fatal (an integration must never take the engine down). A restart re-runs the
   handshake, and the re-described capabilities are re-checked against enablement (`§6.3`).

Spawning is lazy: an installed, enabled adapter is started on first resolver demand or first
health probe, not at backend boot. An installed-but-disabled adapter (`§5`) is **never spawned** —
not even for `describe`. Its manifest is the only thing the engine reads, which is exactly why the
manifest exists.

---

## 3. Install layout and the manifest

An installed adapter is a directory:

```
<data>/adapters/<name>/
  manifest.yaml
  <executable>            # or anything exec — a script, a shell wrapper, a JVM launcher
```

`manifest.yaml`:

```yaml
manifest_version: 1
name: okta                     # unique per install; the key tenant config uses
version: 0.3.1                 # adapter's own semver
protocol_versions: [1]         # plugin protocol versions supported (§4.1)
class: NATIVE_API              # 03 §5.4; one class per adapter process
exec: ["./reckon-adapter-okta"]
requires: []                   # ambient runtime prerequisites an author cannot bundle
                               # (e.g. "python3 >= 3.11"); checked by `reckon check` (12 §2)
summary:                       # CLAIMED capabilities — enumeration only, never authority
  verbs: [enumerate_logons, get_entity_context]
  action_types: [account.disable, account.enable]
config_schema: {...}           # CLAIMED copy of §4.3's schema, same status as summary:
                               # lets `reckon check` and an enablement UI render the config
                               # form without spawning a disabled adapter
```

The manifest answers exactly one question: **"what is installed here?"** — cheaply, statically,
without spawning anything. `reckon check`, the catalogs' "installed, not enabled" surface (`§6.2`),
and the enablement UI all read manifests. The `summary` block is a *claim*: it may be stale after
an upgrade and it is never trusted for resolution. The handshake (`§4`) is the sole authority on
what an adapter can actually do; the invariant is **manifest for enumeration, handshake for truth**.

A directory with an unparseable manifest, a duplicate `name`, or no overlapping
`protocol_versions` is reported by `reckon check` and otherwise ignored — a malformed install can
make an adapter invisible, never partially visible.

This layout is deliberately registry-agnostic. The signed-manifest distribution scheme (`05 §6.3`)
produces this layout as its install output; so does a manual copy. Local trust policy for
non-registry installs (checksums, an operator allowlist) is deferred (`§8`).

---

## 4. The handshake

### 4.1 `initialize`

First call after spawn, exactly once per process lifetime:

```
initialize(engine_protocol_versions: [1], engine_version: "…")
  → { protocol_version: 1, adapter_version: "0.3.1", concurrency: 1 }
```

Version negotiation is the highest protocol version both sides support. No overlap → handshake
failure → `UNHEALTHY`. The protocol version is a single integer, bumped only on breaking changes
to the RPC surface; descriptor-schema evolution rides the descriptors' own versioning (`05 §6.4`),
not this number. The stability promise that makes an ecosystem possible: **protocol v1 adapters
keep working against every engine that lists 1 in its supported set.**

### 4.2 `describe`

The source of truth on capability:

```
describe()
  → {
      verbs:        [CapabilityDescriptor…],   # 03 §5.1: verb, inputs, output, intent
      action_types: [ActionDescriptor…],       # 08 §3
      operations:   [op name + param schema…], # what invoke/dispatch will accept
      default_bindings: [Binding…],            # 03 §3.2 / 08 §4 stanzas, ready to adopt
      config_schema: {…},                      # instance configuration schema (§4.3)
    }
```

`describe` is what makes explicit enablement cheap (`§5`): the adapter ships its own default
binding stanzas — parameter templates (`03 §3.3`), target shapes, declared coverage — so enabling
an operation means *naming* it, not *authoring* its binding. Tenant config adopts a default
binding by reference and overrides only where it diverges.

Two hard rules on what `describe` output may do:

- **It proposes, the engine disposes.** Descriptors and default bindings from `describe` enter the
  registries (`05 §6.4`) as *candidates*, filtered by enablement before they exist anywhere an
  agent or analyst can see. `list_capabilities` / `list_action_types` never show a capability the
  tenant has not enabled.
- **The adapter is the authority on what it can do; it is never an authority on how much that
  should be trusted.** `describe` is the source of truth for *capability facts* — facts about the
  adapter: which operations exist, their schemas, what an op mechanically does, which inverse op
  exists. Tier and reversibility classification are not capability facts; they are *risk
  judgments* — facts about the tenant's governance posture — and for those the engine-side catalog
  (`04 §2`) is authoritative. The reason is structural, not stylistic: **tier is an input to
  authorization.** It is `ctx.tier` in Gate 2 policies, and it is what the baseline DENY
  (`AI-no-T3`) and the blast-radius escalator key on (`04 §1`, `§4`). If the adapter's claim set
  the tier, a downloaded third-party binary would control the inputs to its own authorization — a
  vendor adapter could declare `account.disable` T1, ride a tenant's auto-approve-T1 policy, and
  neutralize the baseline DENY by simply never claiming T3. Authorization inputs originate on the
  engine side of the process boundary, full stop. Reversibility splits along the same line: the
  adapter truthfully reports *mechanism* (an inverse op exists, `08 §5`), the catalog decides
  *classification* — whether invoking that inverse earns a `REVERSED` claim in the audit trail or
  only an attempt record (`04 §7.1`; the judgment that made `ioc.block`/`ioc.unblock` BEST_EFFORT
  despite a perfectly good inverse op). Concretely: where the catalog knows an action type, the
  catalog's tier and reversibility win, and a conflicting adapter claim is surfaced at enablement
  time as a drift signal, never silently resolved. An action type the catalog does *not* know
  arrives with no tier; an untiered action type cannot be enabled until the operator assigns one
  (the adapter's claim serving as the visible *proposal*), and the blast-radius escalator can
  still only raise it. This is the same posture as freezing reversibility onto the x-action at
  request time: adapter claims and catalog edits never out-vote the recorded decision.

### 4.3 `configure` — instance configuration

Adapters need per-tenant, non-secret configuration that is neither a credential nor a binding
parameter: a tenant-specific base URL, an org identifier, a timeout. The adapter declares what it
needs; the tenant supplies values; the engine validates and delivers. The author never decides
where values are stored, and the operator never learns an adapter's internals.

**Declaration.** `describe` returns `config_schema` — plain JSON Schema (no new invention:
required/optional, defaults, `description` strings that become prompt text and error messages)
plus one reckon extension:

```json
"config_schema": {
  "type": "object",
  "required": ["org_url"],
  "properties": {
    "org_url":       {"type": "string", "format": "uri",
                      "description": "Okta org base URL, e.g. https://acme.okta.com"},
    "api_timeout_s": {"type": "integer", "default": 30},
    "client_secret": {"type": "string", "x-secret": true}
  }
}
```

**The `x-secret` rule.** A field marked `x-secret` is the seam between config and credentials:
the engine *requires* its value in tenant config to be a vault reference and refuses a literal at
config load. Secret-marked values are resolved per-invocation alongside `credentials_ref`
(`05 §10.2`) and are passed to `configure` as unresolved refs — plaintext secrets never appear in
the tenant file, in the adapter's environment, or in the handshake. The author marks *which*
fields are secret; the engine's credential posture applies mechanically.

**Supply.** Values live in the instance's enablement stanza (`§5`), under `config:`. Two
validation passes, in the manifest-for-enumeration / handshake-for-truth pattern:

1. **Config load** — validated against the manifest's claimed `config_schema`, without spawning
   anything (the same posture as param templates validating at config load, `03 §3.3`). A missing
   required field fails `reckon check` with the schema's own `description` as the message.
2. **Handshake** — re-validated against the *described* schema (the authority), then delivered as
   the final handshake step: `configure(config)`. The adapter may reject with a diagnostic →
   `UNHEALTHY`, surfaced like any health failure.

**Drift** rides `§6.3`: an upgrade that adds a required config field the tenant hasn't set marks
the instance unavailable with a diagnostic naming the field — config is never guessed. A new
optional field with a default changes nothing.

---

## 5. Enablement: explicit at two levels

Nothing an installed adapter describes is live by default. **There is no auto-bind.** Enablement
is tenant config (the same file as `03 §3.2`), and it is two gates deep:

```yaml
adapters:
  okta:
    enabled: true                # gate 0 — without this, the adapter is never even spawned
    config:                      # instance configuration, validated per §4.3
      org_url: https://acme.okta.com
      client_secret: vault://okta/client-secret   # x-secret field: a literal here is a
                                                  # config-load error
    reads:
      - enumerate_logons         # per-op, explicit…
      - get_entity_context
    # reads: all                 # …or the one wildcard that exists, as a deliberate opt-in
    actions:
      account.disable: {}        # {} = adopt the adapter's default binding verbatim
      account.enable:
        priority: 10             # overrides only where the tenant diverges (03 §3.2 fields)
```

**Named instances.** The key under `adapters:` is an *instance* name; an optional `adapter:`
field names the installed adapter it runs, defaulting to the key — so the single-instance config
above is the degenerate case and pays nothing. Two Okta orgs are two instances of one install:

```yaml
adapters:
  okta-acme:   {adapter: okta, config: {org_url: "https://acme.okta.com"},       reads: [...]}
  okta-subsid: {adapter: okta, config: {org_url: "https://subsidiary.okta.com"}, reads: [...]}
```

Each instance is its own process, own `configure`, own enablement lists, own bindings, own
health; binding references (`03 §3.2`) name instances, not installs. Instance identity is settled
now, in v0, because retrofitting it later would churn every binding reference; the feature costs
one optional field.

The read/write asymmetry is the load-bearing decision:

- **Reads: per-op, or an explicit `reads: all`.** The wildcard is one deliberate line, and the
  worst case of a misbehaving read adapter is garbage observations — which provenance (`03 §4`)
  attributes and bounds. Tenants who want the 15-checkbox ceremony can have it; tenants who don't,
  opt out in writing.
- **Writes: per-op, no wildcard, ever.** Each action type an adapter may serve is named
  individually. An adapter that can disable accounts appearing in the action catalog because a
  directory landed on disk is the wrong failure mode for this product; five explicit lines for a
  containment adapter is the intended cost. `08 §4` binding semantics (no-fall-through, one
  binding chosen per dispatch) are unchanged — this list decides only which bindings exist.

Enablement composes with, and never substitutes for, the dynamic layer: every dispatch still
walks Gate 2, trust tiers, and the blast-radius escalator (`04`) at request time. Because the
per-request judgment lives there, this layer can stay a checklist — it decides the *surface*, not
the *policy*. Resist per-op conditions or constraints in this config; that is Gate 2's job, and
duplicating it here would create a second, worse policy engine.

Enablement is config-plane, not investigation-plane: editing it is an operator/tenant-admin act.
In v0 solo-localhost those are the same person editing the same YAML; the seam matters when a UI
fronts this config (the checklist renders in the extension, the authority stays in tenant config)
and when tenancy separates the roles (`05 §4`).

Hand-editing is the escape hatch, not the intended experience. Because every question a setup
flow must ask is *derived* — config prompts from the `§4.3` schema (descriptions and defaults
included), op checklists from `describe` filtered through the catalog, tier annotations from
`§4.2` — an interactive `reckon adapter enable <instance>` and a schema-generated form in the
extension both come nearly for free, and both write the same YAML an operator could write by
hand. Secrets are the flow's one materially better path: the operator pastes a value once, the
engine stores it in the vault and writes the `vault://` ref into the config itself. The design
rule: **the tenant config file stays the single source of truth; every tool is sugar that edits
it** — so the file remains diffable, reviewable, portable to an airgapped box, and `reckon check`
validates it identically no matter who or what wrote it.

---

## 6. Fail-closed rules

### 6.1 Install

Installing an adapter changes nothing but the output of `reckon check` and the "installed, not
enabled" surface. No spawn, no catalog entry, no binding.

### 6.2 Visibility of the disabled

The catalogs gain a third axis alongside health: a capability can be *installed but not enabled*.
`list_capabilities` / `list_action_types` (`03 §2.8`, `§6.3`) do **not** show these to the agent —
the LLM sees only what is usable. They surface to the *operator* (in `reckon check` and the future
enablement UI), so newly installed or newly added capability is discoverable without being active.

### 6.3 Drift

An adapter upgrade that adds new verbs or action types ships them **disabled**: new capability
never rides an existing enablement. The engine detects drift by diffing `describe` output against
the enablement list at handshake time:

- Enabled op no longer described → that op's bindings go unavailable (surfaced as such per
  `03 §6.1`/`§6.3`); enablement config is never silently edited.
- Newly described op → joins the installed-not-enabled surface, nothing more.
- Changed default binding for an adopted op → the new default applies only where the tenant hadn't
  overridden; a changed *param schema* that invalidates the tenant's overrides marks the binding
  unavailable with a diagnostic rather than dispatching on a guess.
- Changed `config_schema` → the instance's `config:` block is re-validated (`§4.3`); a new
  required field the tenant hasn't set marks the *instance* unavailable with a diagnostic naming
  the field. A new optional field with a default changes nothing.

The same rule at first enablement: `enabled: true` with empty `reads`/`actions` enables nothing.

---

## 7. Conformance

The contract is only an ecosystem seam if someone who has never read this repo can verify an
implementation against it. The pieces exist: the fixture layer (`03 §9`, `08 §9`) defines
scenario data, and the `FIXTURE` adapter is a reference implementation of the semantic contracts.
v0 ships the missing piece as a CLI verb:

```
reckon adapter test <path-to-adapter-dir>
```

which spawns the adapter, runs the handshake, validates `describe` output against the descriptor
schemas, exercises declared operations against scenario fixtures, and asserts the `03 §6.2` error
taxonomy on injected failures. Passing conformance is the definition of "speaks the protocol."
The intended authoring loop — scaffold, implement, `reckon adapter test`, install — is what
"streamlined" means in practice; a conformance suite is cheaper than a support burden.

---

## 8. Open questions / deferred to v1+

- **Local trust for non-index installs** — *settled by `12 §5.3`*: verification gates are
  independent, so a manual install skips digest and signature verification but keeps conformance,
  enablement, and Gate 2 unconditionally; `reckon check` labels it `unverified-origin` so the
  narrowing is visible. No operator-recorded checksum is required — the residual exposure is an
  operator who both installed and enabled a malicious adapter, which no local checksum ceremony
  would change.
- **Socket/remote transport.** stdio assumes parent-child on one host. The cloud-side worker
  fleet (`05 §6.1`) and long-lived adapters (connection-pooling daemons) want a socket or HTTP
  carrier for the same RPC surface. Deferred; the protocol is transport-agnostic by construction.
- **Handshake-supplied normalizers.** An adapter emitting a custom OCSF class (`03 §4.14`) today
  relies on the engine's opaque default normalizer (`03 §4.13`). Whether an adapter should be able
  to ship normalization *hints* (field mappings, not code) in `describe` is open; shipping code is
  ruled out (normalization is engine-side and pure, `03 §4`).
- **Multi-class adapters.** One process, one class keeps the model legible; a vendor suite
  wanting read verbs and write ops in one binary currently ships two adapters sharing a client
  library. If that proves heavy in practice, allowing one process to describe both surfaces is a
  protocol-compatible relaxation.
- **Enablement provenance.** Whether flipping an op from disabled→enabled should itself be a
  recorded, attributed event (config-plane audit) rather than a config-file diff. Leans yes once
  tenancy separates operator from analyst; v0's config file under version control is an
  acceptable interim answer.

---

*End of spec. The semantic contracts this protocol carries are `03 §5` (read) and `08 §5` (write);
how an adapter directory arrives verified is `12-adapter-distribution.md`; the authorization layer
that enablement must never be confused with is `04`.*
