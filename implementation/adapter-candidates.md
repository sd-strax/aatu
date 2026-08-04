# Adapter candidates and the CrowdStrike plan

Phase E moves the capability/action layers off fixtures onto real tools. The
contracts are already built and authoritative — the read `Adapter` and write
`WriteAdapter` interfaces (`capability/adapter.go`, `action/writeresult.go`; specs
`03 §5`, `08 §5`), the five adapter classes, the error taxonomy, the verb resolver,
and every v0 OCSF normalizer. What is missing is the out-of-process transport
(`design/11 §2`), any real adapter, and distribution (`design/12`).

This note captures (1) the initial list of vendor MCP servers worth adopting and
(2) the concrete scope of the first CrowdStrike adapters. It is a plan against the
specs, not a re-statement of them — the contracts live in `03`/`08`/`11`/`12`.

**Design posture: prefer vendor-supported MCP where it exists.** `11 §1.1` frames an
MCP wrap as "a thin, mostly mechanical bridge" — the mature MCP client handles the
transport, auth flows, and schema discovery a native adapter would hand-roll. The
caveat that survives: **MCP removes the plumbing, not the semantics.** A reckon MCP
adapter still maps reckon verbs ↔ vendor MCP tools and shapes the vendor's output
into OCSF. That normalization is the same work regardless of transport (there is no
normalizer on the write path; reads always normalize — `03 §4`).

---

## 1. Candidate list (vendor-official MCP, SOC domain)

Tiered by maturity. "Class" is the reckon adapter class (`capability/adapter.go`).
Only vendor-official/supported servers are listed; community-only servers
(e.g. VirusTotal's `burtthecoder` server) are deliberately excluded — an adapter
holds tenant credentials and can dispatch containment, so provenance is not
optional. Ordering within this note is on **technical readiness only** (official
status, transport simplicity, surface coverage); nothing here is a delivery
commitment.

| Vendor MCP | Status | Class | Surface | reckon verbs / action-types |
|---|---|---|---|---|
| **CrowdStrike Falcon** (`crowdstrike/falcon-mcp`) | Official, **public preview** | mcp | read + partial write | `get_host_context`, detections/incidents, intel; `ioc.block`/`ioc.unblock` (custom IOC). See §3 — host isolation is the gap. |
| **Okta** (`okta/okta-mcp-server`) | Official, **GA**, self-hosted stdio | mcp | read + write | user/group lookup; `account.disable`/`account.enable` |
| **GreyNoise** (`GreyNoise-Intelligence/greynoise-mcp-server`) | Official (2025-09) | mcp | read | IP reputation / noise-vs-targeted → IOC enrichment |
| **Atlassian** (`atlassian/atlassian-mcp-server`) | Official, remote HTTP, Cloud-only | mcp | write | `ticket.create`/`ticket.transition`/`ticket.comment` (Jira + JSM) |
| **Splunk** (Splunkbase app 7931) | Official (Splunk LLC), supported/**beta**, HTTP | mcp | read | SPL → auth/process/network telemetry, saved searches |
| **Google SecOps / Chronicle** (`google/mcp-security`) | Official, remote/managed | mcp | read | events, alerts, entity lookup (IP/domain/hash), IoC matches; bundles Google Threat Intel |
| **Microsoft Sentinel** | Official, **GA** (2025-11), remote/managed | mcp | read | KQL over the data lake, entity graph |
| **Elastic** (`@elastic/mcp-server-elasticsearch` → Agent Builder) | Official; standalone **deprecated**, superseded by managed Agent Builder | mcp | read | index search/DSL → telemetry |
| **ServiceNow** (MCP Server Console / Now Assist Skills) | Official-ish, governance-gated | mcp | write | `ticket.*` in the SNOW system of record |
| **Tines** (stories → MCP server) | Official feature | soar_playbook | write | SOAR playbook dispatch |
| **AWS** (AWS Labs, CloudTrail MCP) | Official (2025-09) | mcp | read | CloudTrail event/Lake queries → cloud telemetry |

**Excluded:** Torq — it is an MCP *host* (it consumes MCP), so it occupies reckon's
role rather than being a server reckon can wrap.

### The transport wrinkle (load-bearing)

reckon's v0 plugin transport (`11 §2`) is **one adapter = one local executable,
JSON-RPC over stdio** (parent-child). Several official servers above — Sentinel,
Chronicle, Atlassian, Elastic Agent Builder — are **remote-hosted HTTP** MCP
endpoints. Socket/remote transport is the `11 §8` deferred slot.

This is not a blocker: the reckon MCP adapter is a **local bridge process** that
speaks reckon-stdio to the engine on one side and holds an MCP client (stdio-spawn
*or* remote-HTTP) to the vendor on the other. The HTTP-vs-stdio mismatch is absorbed
inside the bridge. Pure-stdio vendor servers (Okta self-hosted, falcon-mcp local)
are the simplest first targets because both hops are stdio.

### Recommended first cut (technical-readiness grounds)

1. **Okta** — GA, self-hosted (pure stdio, simplest transport), write-capable
   (`account.disable`). Best *first* adapter: proves the E.1 transport end to end
   against a real vendor with a real write action.
2. **GreyNoise** — official, focused, read-only; smallest OCSF-mapping surface.
3. **CrowdStrike** — the hybrid in §3 (highest utility, some preview churn).
4. **Atlassian JSM** — real `ticket.create` replacing the fixture write adapter.

CrowdStrike is second-in-importance to Okta only for *bring-up ordering* (Okta is
the cleaner transport shakedown); by utility it is the marquee integration, which
is why its plan is scoped in full below.

---

## 2. Prerequisite: the out-of-process transport (E.1)

**Status: E.1 is built (see §4 milestone 1).** No adapter here could be built
before the plugin transport existed; it now does. E.1 delivered `design/11 §2`–`§4`:

- Spawn + supervise a child process; **JSON-RPC 2.0 over stdio**; `initialize` →
  `describe` → `configure` handshake; `invoke`/`dispatch`/`health` mapped 1:1 onto
  JSON-RPC methods; lazy spawn; budgeted-restart supervision (never fatal — an
  integration must not take the engine down).
- The manifest + install layout (`11 §3`) and two-level enablement (`11 §5`:
  adapter gate + per-op allowlist).

**Reuse:** `internal/sidecar/` already implements LSP-framed JSON-RPC 2.0 over
stdio for the *agent* channel (workbench↔engine). The adapter channel
(engine↔adapter) is a different peer with the same framing/conn plumbing — E.1 is
"mirror the sidecar's framing for a new peer," not greenfield. The `describe`
handshake is the authority on adapter capability — `11 §3` "manifest for
enumeration, handshake for truth" — so the build never trusts a vendor's docs over
what the live adapter reports.

---

## 3. CrowdStrike: the hybrid, two adapters

**Finding.** The official `falcon-mcp` (public preview) is read-strong and does
*some* writes (custom IOC create/remove → `ioc.block`), but the marquee containment
action is the soft spot: **RTR is read-only in the MCP, and containment surfaces as
host-*group* management, not a first-class per-host contain/lift tool.** The Falcon
*platform* does one-shot network containment (`PerformActionV2` contain/lift, scope
`hosts:write`) — it is simply not reliably exposed through the preview MCP.

**Decision.** Split CrowdStrike by surface — sanctioned by `11 §8` ("a vendor suite
wanting read verbs and write ops currently ships two adapters sharing a client
library"). The verb resolver binds verbs→adapters by priority (`03 §3`), so both
point at the same tenant transparently. This makes CRWD the first real exercise of
the transport-neutral premise: **MCP where it's clean, native where it isn't, same
vendor.**

Why the preview churn is tolerable: reckon's plugin model degrades gracefully on a
moving target. `describe` re-runs on restart and re-checks against enablement
(`11 §6.3`); a changed/removed tool makes its verbs **unavailable** in
`list_capabilities` (honest degradation, `03 §6.3`), never a crash or a mis-dispatch;
per-op enablement (`11 §5`) means a newly-appeared preview tool cannot auto-surface
to analysts. Consuming a churning preview is close to the model's best case.

### Adapter A — `crowdstrike-falcon` (class: `mcp`, read + IOC write)

Wraps `crowdstrike/falcon-mcp`. Bridge process: reckon-stdio ↔ engine; MCP client ↔
falcon-mcp (local stdio subprocess in v0).

Manifest (`11 §3`):
```yaml
manifest_version: 1
name: crowdstrike-falcon
version: 0.1.0
protocol_versions: [1]
class: MCP
exec: ["./reckon-adapter-crowdstrike-falcon"]
requires: ["python3 >= 3.11"]   # falcon-mcp is a Python package (pip install falcon-mcp)
summary:
  verbs: [get_host_context, enumerate_detections, get_intel_context]
  action_types: [ioc.block, ioc.unblock]
config_schema: {...}            # Falcon cloud region + credentials_ref (05 §10.2)
```

Read operations (`Adapter.Invoke` → normalize → OCSF):

| reckon verb | falcon-mcp tool | Falcon scope | OCSF / normalizer |
|---|---|---|---|
| `get_host_context` | Hosts/Discover query | `hosts:read` | device-inventory shape (as the existing `get_host_context` fixture) |
| `enumerate_detections` | Detections search | `detections:read` | `detection_finding` normalizer (`03 §4.12`, INFERRED exception) |
| `get_intel_context` | Intel / Spotlight | `intel:read` | IOC/indicator enrichment → SCO + ObservedData |

Write operations (`WriteAdapter.Dispatch` → `WriteResult`, no normalizer):

| action-type | falcon-mcp tool | Falcon scope | reversibility |
|---|---|---|---|
| `ioc.block` | custom IOC create | `ioc:write` | best_effort (`ioc.unblock`) |
| `ioc.unblock` | custom IOC remove | `ioc:write` | — |

Deliberately **NOT** on this adapter: `host.isolate` (see Adapter B). Bind only
verbs the live `describe` reports; anything the preview later adds is picked up on
restart, not assumed here.

### Adapter B — `crowdstrike-response` (class: `native_api`, host isolation)

A deliberately tiny native adapter doing the marquee action the preview MCP does
not reliably expose. falconpy SDK (or a hand-rolled HTTPS client), one operation
family.

Manifest:
```yaml
manifest_version: 1
name: crowdstrike-response
version: 0.1.0
protocol_versions: [1]
class: NATIVE_API
exec: ["./reckon-adapter-crowdstrike-response"]
requires: []                    # static binary or vendored deps (12 §2)
summary:
  action_types: [host.isolate, host.unisolate]
config_schema: {...}            # Falcon cloud region + credentials_ref
```

Write operations:

| action-type | Falcon operation | Falcon scope | reversibility (catalog) |
|---|---|---|---|
| `host.isolate` | `PerformActionV2` action=`contain` | `hosts:write` | reversible → `host.unisolate` (matches `action/descriptor.go`) |
| `host.unisolate` | `PerformActionV2` action=`lift_containment` | `hosts:write` | reversible → `host.isolate` |

`Dispatch` returns a `WriteResult` (`action/writeresult.go`): `FinalOutcome` +
`PerTargetResults` per device id, `AdapterRequestID` = the Falcon action batch id,
`AuditDepth` = the vendor boundary. The target is the host (`resolved_identifier` =
Falcon device id / hostname), matching the `host.isolate` descriptor. The
**no-fall-through** rule (`08`, `action/resolver.go`) is exactly right here: a partial
containment must never silently re-attempt against another tool.

### What CRWD needs on the reckon side (not free with MCP)

- **Normalizers.** `get_host_context` → device-inventory shape; `enumerate_detections`
  → `detection_finding` (exists). Any Falcon-specific OCSF class beyond the v0 set
  falls to the opaque default normalizer (`03 §4.13`) until a dedicated one lands.
- **Credentials.** Falcon `client_id`/`client_secret` resolve via `credentials_ref`
  (`05 §10.2`), per-invocation, never in the adapter's environment (`11 §2`).
- **Two example configs.** A tenant capability YAML binding the read verbs to
  `crowdstrike-falcon`, and an action config binding `host.isolate`/`host.unisolate`
  to `crowdstrike-response` — mirroring `examples/capability/lateral-movement.yaml`
  and `examples/action/lateral-movement.yaml`.

---

## 4. Milestones

1. **E.1 — DONE.** Plugin transport (`11 §2`–§4), manifest + enablement
   (`11 §3`,`§5`), mirrored from `internal/sidecar/`. Landed as
   `internal/adapterplugin/` (framing/conn/manifest/handshake/host/facades +
   budgeted-restart supervision), the runtime scan+inject wiring, the §5
   enablement config fields, the `reckon adapter test` conformance verb (`§7`),
   the `cmd/reckon-adapter-echo` reference adapter, and secret-ref resolution
   (`internal/secretref/`: keychain://·env://·vault:// with x-secret
   literal-refusal at config load, `§4.3`). **v0 resolves secrets at `configure`
   time**; the per-invocation credential channel (`05 §10.2`) is the deferred
   hardening. Blocks nothing further.
2. **E.2** — Okta MCP adapter (transport shakedown: pure stdio, `account.disable`).
3. **E.3** — GreyNoise MCP adapter (read-only OCSF-mapping shakedown).
4. **E.4 — CrowdStrike:** Adapter A (`crowdstrike-falcon`, MCP read + IOC), then
   Adapter B (`crowdstrike-response`, native host isolation). Ship the two example
   configs; validate the read verbs against a live `describe`; confirm
   `host.isolate`→`host.unisolate` reversal drives the existing `ReversalSaga`.
5. **E.5** — distribution (`design/12`) is deferrable: `12 §5.3` supports non-index
   installs (`git clone && make`, manual copy), so real adapters run long before the
   signed-index machinery exists.

## 5. Open questions / risks

- **falcon-mcp tool churn.** Public preview; the exact tool surface changes before
  1.0. Mitigation is structural (§3): `describe`-driven binding + fail-closed drift.
  Re-verify Adapter A's verb bindings at each falcon-mcp bump; the native Adapter B
  is insulated (it never touches the MCP).
- **Remote-HTTP vendor MCP (Sentinel/Chronicle/Atlassian).** v0 bridges hold the
  HTTP client locally; a first-class socket/remote transport is `11 §8`, wanted once
  a remote-hosted server is a primary target.
- **Falcon device-inventory normalizer.** The `get_host_context` OCSF shape is
  fixture-defined today; the real falcon-mcp host payload needs a normalizer pass
  before Adapter A's read surface is trustworthy.
- **Multi-class-per-vendor ergonomics.** CRWD is the first two-adapter vendor; if
  the shared-client-library duplication proves heavy, `11 §8`'s one-process-two-
  surfaces relaxation is the escape hatch.
