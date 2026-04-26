# Capability Layer Specification

A self-contained design for the abstraction between LLM/analyst and the SOC's
heterogeneous tool ecosystem in the investigation environment. This spec
consumes the Investigation Domain Model as its authoritative dependency and
produces a vendor-neutral, transport-neutral capability surface that normalizes
tool outputs into STIX-shaped observations and OCSF events.

---

## 1. Design Principles

The capability layer exists to keep three things clean: the LLM's tool-selection
space, the domain model's invariants, and the framework's extensibility. Every
design choice below derives from one of those.

**Vendor neutrality is achieved by intent verbs, not lowest-common-denominator
schemas.** A capability expresses *what the analyst is trying to learn*, not the
union or intersection of what every EDR happens to expose. If a vendor cannot
fulfill a capability, that is a graceful-degradation problem, not a schema
problem.

**Transport is an adapter concern, not a layer concern.** The capability layer
is agnostic to whether a tool speaks MCP, REST, GraphQL, gRPC, SQL, or reads
files off disk. MCP is one transport among several — preferred where it exists
and is production-ready, but not assumed. What matters is that every adapter
produces well-formed OCSF events at its outbound boundary. By the time data
crosses the adapter boundary into the capability layer, transport details are
gone.

**The capability layer is pure I/O plus normalization.** It does not reason. It
does not produce `x-interpretation` records (Interpretations live inside the
investigation aggregate per persistence.md §2.1; the agent loop is their only
legal author). It does not make hypothesis judgments. Its outputs are typically
`derivation_mode = DIRECT` because every observation it emits traces to a real
tool call. The single exception is the `detection_finding` normalizer (§4.12),
which emits Indicators and Sightings with `derivation_mode = INFERRED` and
`provenance.tool = vendor_name` because vendor detections are themselves
inferences — just made upstream of our system. Even there, the capability
layer never wraps the imported nodes in an Interpretation; the agent loop does
that when an investigation engages with them.

**Identity is computed once, at the normalizer boundary.** Cross-tool stitching
depends on every producer arriving at the same UUIDv5 for the same entity. The
normalizer is the only place identity is computed, and the rules are
deterministic and documented.

**Raw responses are sacred.** Every tool response becomes an immutable
`OcsfEvent` before any normalization runs. Normalization can be re-run, fixed,
versioned, or replayed; the raw payload is the ground truth and never mutated.

---

## 2. Verb Catalog

The v1 capability set is 22 verbs, grouped by intent. Each verb has a typed
signature referencing domain model types. Inputs are described as parameter
records; outputs are STIX objects (and the implicit `OcsfEvent` always written
to telemetry).

Conventions for signatures: `Entity` means a STIX SCO id or a canonical
identifier (string) the layer will resolve. `TimeWindow` is
`{ from: timestamp, to: timestamp }`. `Limit` is an optional integer with
per-verb defaults. Every verb returns, in addition to its declared outputs, a
`CapabilityResult` envelope:

```
CapabilityResult {
  ocsf_event_refs:    list<OcsfEvent.id>      // every raw response written
  observed_data_refs: list<ObservedData.id>   // normalized observations
  entity_refs:        list<Entity.id>         // SCOs extracted/resolved
  provenance:         Provenance              // uniform fields
  coverage:           Coverage                // structured outcome (see §6)
  degradation_notes:  list<string>            // human-readable detail
}

Coverage = COMPLETE
         | PARTIAL                  // some bindings succeeded, some failed
         | UNAVAILABLE_TENANT       // no binding exists for this verb in tenant
         | UNAVAILABLE_TRANSIENT    // bindings exist, all currently unhealthy
         | FAILED                   // bindings healthy, all calls failed
```

The agent loop is what attaches these refs to an `x-interpretation` of type
`extraction`. The `coverage` field is structured so the agent loop can branch
on outcome class without parsing prose; `degradation_notes` carries
human-readable detail (e.g., which adapters failed and why).

### 2.1 Entity resolution and context

**`resolve_entity(identifier: string, hint_type?: EntityType) -> Entity`**
Canonicalizes a free-form identifier (e.g., `"8.8.8.8"`, `"contoso\\jdoe"`,
`"WIN-DC01"`) into a STIX SCO with a deterministic UUIDv5 id. Does not call
external tools unless `hint_type` is unknown and disambiguation requires a
directory lookup. This is the canonical entry point for entering an
investigation by entity.

**`get_user_context(user: Entity) -> {user_account: Entity, group_memberships: list<Entity>, manager_ref?: Entity, account_status: string}`**
Pulls IdP/directory context for a user (Entra ID, AD, Okta). Output is one or
more `user-account` SCOs plus relationships materialized as ObservedData.

**`get_host_context(host: Entity) -> {host: Entity, owner_ref?: Entity, os: string, last_seen: timestamp, sensors: list<string>}`**
Asset/CMDB context for a host. Returns enriched `x-host`.

**`get_indicator_context(indicator: Entity) -> {ti_matches: list<ObservedData>, reputation: string, first_seen?: timestamp}`**
Threat-intel enrichment for an IP, domain, hash, or URL.

### 2.2 Process and execution

**`get_process_ancestry(process: Entity, depth?: int = 5) -> list<ObservedData>`**
Walks parent chain of a process. Outputs ordered ObservedData each linking
parent-child `process` SCOs.

**`get_process_descendants(process: Entity, depth?: int = 3, limit?: int = 100) -> list<ObservedData>`**
Children/grandchildren of a process. Outputs ObservedData with parent and
descendant `process` SCOs.

**`get_process_executions(filter: ProcessFilter, window: TimeWindow, limit?: int = 200) -> list<ObservedData>`**
Search for process executions matching a filter
(`{image_hash?, image_path?, command_line_contains?, host?, user?}`). OCSF class
1007 maps directly.

**`get_module_loads(process: Entity, window: TimeWindow) -> list<ObservedData>`**
DLLs/modules loaded by a process. OCSF class 1009 (module_activity) where
vendors expose it.

### 2.3 Authentication and access

**`enumerate_logons(target: Entity, window: TimeWindow, outcome?: SUCCESS|FAILURE|ALL) -> list<ObservedData>`**
Logons to or by a host/user. OCSF class 3002. `target` may be a `user-account`
or `x-host`.

**`get_failed_auth_burst(target: Entity, window: TimeWindow, threshold?: int = 5) -> list<ObservedData>`**
Convenience verb returning failed auth bursts above threshold. Same telemetry as
`enumerate_logons` but pre-filtered server-side where the underlying tool
supports it.

**`get_privilege_changes(target: Entity, window: TimeWindow) -> list<ObservedData>`**
Group membership and privilege grants/revocations. OCSF class 3005
(account_change).

### 2.4 Network and lateral movement

**`get_network_connections(endpoint: Entity, window: TimeWindow, direction?: INBOUND|OUTBOUND|ALL, limit?: int = 500) -> list<ObservedData>`**
Network conns from/to a host, IP, or process. OCSF class 4001.

**`resolve_dns(name: Entity | string, window: TimeWindow) -> list<ObservedData>`**
DNS resolutions. OCSF class 4003.

**`get_lateral_movement_signals(host: Entity, window: TimeWindow) -> list<ObservedData>`**
Composite verb: surfaces remote logons, SMB/WMI/RDP traffic, and process
executions consistent with lateral movement. Returns ObservedData with
`derivation_mode = DIRECT` per source; the agent decides what's a hypothesis.

### 2.5 File and persistence

**`get_file_activity(file: Entity, window: TimeWindow) -> list<ObservedData>`**
Reads/writes/deletes touching a file or hash. OCSF class 1001.

**`get_persistence_artifacts(host: Entity, window: TimeWindow) -> list<ObservedData>`**
Registry run keys, scheduled tasks, services, autoruns, WMI subscriptions.
Vendor-specific OCSF classes (1003 registry_key_activity, 1006
scheduled_job_activity, etc.).

### 2.6 Email and identity

**`get_email_messages(filter: EmailFilter, window: TimeWindow, limit?: int = 100) -> list<ObservedData>`**
Email metadata (sender, recipient, subject, attachments, urls, verdict). OCSF
class 4009 (email_activity).

**`get_email_clicks(user: Entity, window: TimeWindow) -> list<ObservedData>`**
URL clicks from email. OCSF class 4011 where exposed; otherwise vendor-specific.

### 2.7 Generic queries and pivots

**`query_logs(spec: QuerySpec, window: TimeWindow, limit?: int = 1000) -> list<ObservedData>`**
Escape hatch for SIEM-style queries against Splunk/Sentinel/Chronicle.
`QuerySpec = {tool, query_text, parameters}`. Result is normalized best-effort:
rows with recognizable fields become typed ObservedData; others are wrapped as
opaque ObservedData with the raw OcsfEvent attached. The agent should prefer
typed verbs and fall back to `query_logs` only when no typed verb fits.

**`pivot_on_indicator(indicator: Entity, window: TimeWindow, scopes?: list<string>) -> list<ObservedData>`**
Fan-out search across all telemetry sources for sightings of an indicator.
`scopes` filters to e.g. `["edr", "proxy", "email"]`.

**`search_alerts(filter: AlertFilter, window: TimeWindow) -> list<ObservedData>`**
Detection findings/alerts touching an entity or matching criteria. OCSF class
2004 (detection_finding).

### 2.8 Capability discovery

**`list_capabilities(tenant?: string) -> list<CapabilityDescriptor>`**
Returns the capabilities resolvable in the current tenant, including which are
degraded or unavailable. Used by the agent loop on session start to right-size
the tool set advertised to the LLM.

---

A note on the count: 22 verbs hits the upper end of the 15-25 target. I
considered collapsing `get_failed_auth_burst` into `enumerate_logons` and
`get_email_clicks` into `get_email_messages`. I kept them separate because they
map to distinct analyst intents and benefit from server-side pre-filtering when
the underlying tool supports it. If schema budget becomes a problem, those four
are the first candidates to merge.

---

## 3. Resolution Model

### 3.1 Approach

Resolution is **declarative mapping with pluggable adapters**, not a rule
engine. Every verb has one or more `CapabilityBinding`s per tenant. A binding
names the adapter (e.g., `crowdstrike_falcon`, `defender_xdr`, `splunk_es`), the
concrete operation on that adapter, and a parameter mapping. At call time the
resolver picks the highest-priority binding whose preconditions are satisfied
(entity type matches, required tool features available, tenant has credentials
configured).

A rule engine was rejected because the matching logic is structural (verb +
entity types + tenant capabilities), not behavioral. Declarative bindings are
diff-friendly, version-controllable, and lend themselves to the extension story
below.

### 3.2 Tenant config

Tenant config is YAML, loaded at startup and watchable for hot-reload. The
shape:

```yaml
tenant: acme-corp
adapters:
  crowdstrike_falcon:
    class: native_api          # mcp | native_api | custom | fixture
    base_url: https://api.crowdstrike.com
    credentials_ref: vault://acme/cs
    enabled: true
  defender_xdr:
    class: native_api
    tenant_id: 11111111-2222-3333-4444-555555555555
    credentials_ref: vault://acme/m365
    enabled: true
  splunk_es:
    class: native_api
    base_url: https://splunk.acme.internal:8089
    credentials_ref: vault://acme/splunk
    enabled: true
  acme_cmdb:
    class: custom              # homegrown REST service
    base_url: https://cmdb.acme.internal
    credentials_ref: vault://acme/cmdb
    enabled: true
  threat_intel_mcp:
    class: mcp
    server_url: https://ti.partner.com/mcp
    credentials_ref: vault://acme/ti
    enabled: true
  fixture:
    class: fixture
    enabled: false             # toggled true in v0 / dev / replay

bindings:
  get_process_ancestry:
    - adapter: crowdstrike_falcon
      operation: rtr.process_tree
      priority: 100
      params:
        device_id: "${entity.host.external_id}"
        process_id: "${entity.process.pid}"
    - adapter: defender_xdr
      operation: advanced_hunting
      priority: 50
      params:
        kql: |
          DeviceProcessEvents
          | where DeviceId == "${entity.host.external_id}"
          | where ProcessId == ${entity.process.pid}
          | ...
  enumerate_logons:
    - adapter: defender_xdr
      operation: advanced_hunting
      priority: 100
      params: { ... }
    - adapter: splunk_es
      operation: search
      priority: 80
      params: { ... }
  get_host_context:
    - adapter: acme_cmdb
      operation: assets.lookup
      priority: 100
      params: { hostname: "${entity.host.hostname}" }
  get_indicator_context:
    - adapter: threat_intel_mcp
      operation: lookup
      priority: 100
      params: { indicator: "${entity.value}" }

policies:
  default_window:
    investigation: PT24H
    hunt: PT7D
  rate_limits:
    per_adapter_qps: 5
  caching:
    default_ttl: PT15M
```

The resolver algorithm:

1. Receive `(verb, params, tenant)`.
2. Look up bindings for `verb` in tenant config, sorted by priority desc.
3. For each binding, check adapter is enabled, credentials are valid, and
   required input fields are present.
4. Render parameter template against the input.
5. Invoke the adapter; on success, return the raw response to the OCSF writer
   and then the normalizer.
6. On binding failure (adapter down, auth error, schema mismatch), proceed to
   next binding. On all bindings exhausted, return a partial `CapabilityResult`
   with `degradation_notes`.

Why priority rather than a single binding per verb: in real tenants, the "best"
tool depends on the entity. If an EDR has the host but the process originated
from a logon visible only to the IdP, you want the resolver to try the EDR
first, fall through to the SIEM if the device isn't enrolled, and surface
partial results rather than throwing. Priority + preconditions gives you that
without writing a rule DSL.

### 3.3 Parameter templating

Bindings render concrete adapter parameters from the capability call's input by
template expansion. The template language is **string substitution with
typed-path references and a sealed-but-extensible function set**. It is not a
full expression language; it does not evaluate arbitrary code; it cannot
perform conditionals or loops. This bounded surface is deliberate — the binding
config is the integration surface, written by many people, deployed per
tenant, and "your investigation broke because of a runtime template error" is
not an acceptable failure mode.

#### 3.3.1 Path syntax

Templates appear as `${...}` expressions in YAML scalar values. Three forms:

```
${path.to.field}                 # required: missing field rejects the binding
${path.to.field?}                # optional: missing field omits the param
${path.to.field ?? "default"}    # default: missing field substitutes the literal
```

A path is a dotted reference walked against the binding's input context.
Available path roots:

```
entity        # the input entity, or composite for multi-entity verbs
              #   - single-entity verbs: entity.<field>
              #   - composite verbs:     entity.<role>.<field>
              #     where <role> is the parameter name in the verb signature
              #     (e.g., entity.process.pid, entity.host.hostname)
window        # the TimeWindow input: window.from, window.to
tenant        # tenant config values, for parameterizing by tenant policy
              #   (e.g., tenant.policies.default_window.investigation)
verb          # the verb name itself, useful for adapter-side logging
```

Composite-verb disambiguation: when a verb takes multiple entities (e.g.,
`get_process_ancestry(process)` is single, but the process input itself
references a host), the template path mirrors the input shape:
`${entity.process.pid}`, `${entity.process.host.external_id}`. Adapters
expecting a flat parameter shape must walk the structure themselves; the
templating layer doesn't flatten.

#### 3.3.2 Transformations

Functions are applied with pipe syntax and chain left-to-right:

```
${entity.host.hostname | upper}
${entity.user.account_login | lower | splunk_quote}
${window.from | iso8601}
${entity.process.pid | int}
```

**Built-in functions (always available):**

```
String:    upper, lower, trim
Time:      iso8601, epoch_ms, epoch_s
Type:      int, string, bool
Defaults:  default(value), coalesce(...)
Quoting:   json_quote, json_escape
```

**Adapter-registered functions:** adapters may register additional functions
that exist only in bindings targeting that adapter. The Splunk adapter
registers `splunk_quote`, `splunk_escape`, `spl_field`. The Defender adapter
registers `kql_quote`, `kql_escape`, `kql_table_ref`. The CrowdStrike adapter
registers `cs_device_filter`, `cs_time_format`. This keeps adapter-specific
serialization concerns inside the adapter that owns them, while preserving a
uniform template surface for binding authors.

A binding's templates are parsed and validated against the registered function
set for its adapter at config-load time. Unknown function names cause the
configuration to be rejected at startup; the server does not start with
invalid bindings.

#### 3.3.3 Structured parameters

Templates produce only scalar values. Parameter structure (objects, arrays)
comes from the YAML itself; templates fill leaf values:

```yaml
params:
  device_id: "${entity.host.external_id}"
  process_id: "${entity.process.pid | int}"
  filters:
    - field: "host"
      value: "${entity.host.hostname | lower}"
    - field: "user"
      value: "${entity.user.account_login | lower}"
  options:
    include_children: true
    max_depth: 5
```

This keeps the templating language simple while still expressing arbitrary
parameter shapes. If an adapter needs a dynamically-sized list, the binding
author authors it explicitly in YAML; templates never produce collections.

#### 3.3.4 Validation and failure modes

**Config-load validation** (server startup):

- Every `${...}` expression is parsed; syntax errors reject the config.
- Every path root is recognized (`entity`, `window`, `tenant`, `verb`).
- Every function reference exists in the built-in set or in the target
  adapter's registered set.
- Default-value literals are valid YAML scalars.

If any binding fails validation, the server logs the offending binding and
its tenant, refuses to start, and surfaces the error. Bindings cannot fail
silently into production.

**Runtime validation** (per capability call):

- Required paths (`${path.to.field}` without `?` or `??`) that resolve to
  missing or null values mark the binding **not applicable** for this input.
  The resolver moves to the next priority binding, exactly as if the binding
  did not exist for this entity type.
- Optional paths (`${path.to.field?}`) that resolve to missing values cause
  the containing param to be omitted entirely.
- Type-coercion functions (`int`, `bool`) that fail on non-coercible input
  mark the binding not applicable; same fall-through behavior.
- Adapter-registered functions are responsible for handling their own input
  validation; failures are surfaced as binding-not-applicable.

A binding being not-applicable at runtime is **not** an error from the LLM's
perspective. It contributes to coverage classification (§6) only if all
priority bindings are not-applicable; in that case, the result is
`UNAVAILABLE_TENANT` with a degradation note explaining which inputs were
missing. This surfaces as actionable feedback ("this verb needs a
`host.external_id` we don't have for this entity") rather than as a silent
failure.

#### 3.3.5 What the templating language deliberately does not include

Conditionals, loops, arithmetic beyond type coercion, regular expressions,
arbitrary method calls, file or network access, environment variable
references. If a binding genuinely needs any of these, the right answer is to
extend the adapter (with a registered function or with adapter-side logic)
rather than to extend the templating language. This boundary is the
load-bearing simplification.

### 3.4 Multi-binding fan-out

For a small set of verbs (`pivot_on_indicator`, `search_alerts`, `query_logs`
with scopes), one capability call legitimately should hit multiple adapters and
merge results. These verbs are marked `fanout: true` in the binding config; the
resolver invokes all enabled bindings in parallel, writes one OcsfEvent per
response, and the normalizer dedupes ObservedData by content hash before
returning.

---

## 4. Normalization

Normalization is per-OCSF-class and produces three things: zero or more STIX
SCOs (with computed UUIDv5 ids), one or more `ObservedData` SDOs, and the edges
connecting them to the originating `OcsfEvent`. All outputs carry uniform
provenance.

### 4.1 OCSF process_activity (class_uid 1007) → STIX

Input: an OCSF process_activity event with fields including `process.pid`,
`process.name`, `process.cmd_line`, `process.file.path`, `process.file.hashes`,
`process.parent_process.*`, `device.uuid`, `device.hostname`, `actor.user.name`,
`time`.

Output:

- One `process` SCO for the process: `pid`, `command_line`, `name`, optional
  `created_time`. STIX 2.1 process SCOs are not first-class identifiable by
  themselves; identity is composed (see §7).
- One `process` SCO for the parent process if present.
- One `file` SCO for the executable image, with hashes if present.
- One `x-host` SCO for the device.
- One `user-account` SCO for the executing user if present.
- One `ObservedData` SDO with `object_refs` pointing to all of the above,
  `first_observed = last_observed = time`, `number_observed = 1`.
- Edges: `extracted-from` from each SCO to the `OcsfEvent`; `derived-from` from
  the `ObservedData` to the `OcsfEvent`.
- STIX `Relationship` objects for parent-child (`relationship_type: "parent-of"`
  between the two process SCOs).

### 4.2 OCSF authentication (class_uid 3002) → STIX

Input: OCSF authentication event with `actor.user.name`, `actor.user.domain`,
`dst_endpoint.hostname`, `src_endpoint.ip`, `auth_protocol`, `logon_type`,
`status` (SUCCESS/FAILURE), `time`.

Output:

- One `user-account` SCO for the actor.
- One `x-host` SCO for the destination.
- One `ipv4-addr` (or `ipv6-addr`) SCO for the source IP if present.
- One `ObservedData` SDO referencing all three, plus a `description`-style note
  in custom extension fields recording `logon_type` and `status`.
- Edges as in §4.1.
- An `x-authenticated-to` Relationship between the user and host (derivable from
  STIX `Relationship` with custom type since STIX has no first-class auth
  relationship).

### 4.3 OCSF network_activity (class_uid 4001) → STIX

Input: OCSF network_activity with `src_endpoint.ip`, `src_endpoint.port`,
`dst_endpoint.ip`, `dst_endpoint.port`, `dst_endpoint.domain` (optional),
`connection_info.protocol_name`, `traffic.bytes_in/out`, `time`, optional
`process.pid` and `device.uuid`.

Output:

- `ipv4-addr`/`ipv6-addr` SCOs for source and destination IPs.
- `domain-name` SCO for destination domain if present (with a `resolves-to`
  Relationship to the dst IP).
- `network-traffic` SCO (STIX 2.1 native) wrapping the connection, with
  `src_ref`, `dst_ref`, `src_port`, `dst_port`, `protocols`.
- `process` SCO and `x-host` SCO if process/device info present.
- One `ObservedData` referencing all of the above.
- Edges as in §4.1.

### 4.4 OCSF dns_activity (class_uid 4003) → STIX

Input: OCSF dns_activity with `query.hostname`, `query.type`, `answers[]`
(each with `rdata` and `type`), `src_endpoint.ip`, `time`, optional
`device.uuid`.

Output:

- `domain-name` SCO for `query.hostname`.
- `ipv4-addr` / `ipv6-addr` SCOs for each answer of type A/AAAA.
- `domain-name` SCO for each answer of type CNAME.
- STIX `Relationship` of type `resolves-to` from the queried domain to each
  resolved address (one per A/AAAA answer).
- `ipv4-addr`/`ipv6-addr` SCO for the requesting source if present.
- `x-host` SCO for the device if present.
- One `ObservedData` referencing the queried domain, the answers, and the
  requestor. `first_observed = last_observed = time`.
- Edges as in §4.1.

### 4.5 OCSF file_activity (class_uid 1001) → STIX

Input: OCSF file_activity with `file.name`, `file.path`, `file.hashes`,
`file.size`, `activity_id` (CREATE/READ/MODIFY/DELETE), `actor.process.*`,
`device.uuid`, `time`.

Output:

- `file` SCO for the file, with hashes if present and a `parent_directory_ref`
  pointing to a `directory` SCO if `file.path` carries a directory.
- `directory` SCO for the parent directory.
- `process` SCO for the actor process if present.
- `x-host` SCO for the device.
- `user-account` SCO for the executing user if present in `actor`.
- One `ObservedData` referencing all of the above. The `activity_id` is
  preserved in custom extension fields on the ObservedData (STIX has no
  first-class read/write/modify distinction at the ObservedData level).
- Edges as in §4.1.

### 4.6 OCSF registry_key_activity (class_uid 1003) → STIX

Input: OCSF registry_key_activity with `reg_key.hive`, `reg_key.path`,
`reg_value.name`, `reg_value.data`, `activity_id`, `actor.process.*`,
`device.uuid`, `time`.

Output:

- `x-registry-key` custom SCO with fields `hive`, `key_path`, `value_name`,
  `value_data`. Identity rule: `(host_ref.id, hive, key_path, value_name)`,
  all components lowercased except `value_data`.
- `process` SCO for the actor process.
- `x-host` SCO for the device.
- One `ObservedData` referencing the registry key, actor, and host. The
  `activity_id` (CREATE/MODIFY/DELETE) is preserved in custom extension
  fields.
- Edges as in §4.1.

`x-registry-key` is a custom STIX SCO because Windows registry isn't covered
by STIX 2.1 native types. Identity is host-scoped — registry keys with the
same path on different hosts are different entities.

### 4.7 OCSF scheduled_job_activity (class_uid 1006) → STIX

Input: OCSF scheduled_job_activity with `job.name`, `job.path`,
`job.command_line`, `job.user.name`, `activity_id`, `device.uuid`, `time`.

Output:

- `x-scheduled-task` custom SCO with fields `name`, `path`, `command_line`,
  `principal_user_ref`. Identity rule: `(host_ref.id, name, path)`.
- `user-account` SCO for the principal user (the user the task runs as).
- `x-host` SCO for the device.
- One `ObservedData` referencing all of the above.
- Edges as in §4.1.

`x-scheduled-task` is a custom SCO covering Windows scheduled tasks, cron
entries, systemd timers, launchd jobs, and similar persistence mechanisms.
Identity is host-scoped.

### 4.8 OCSF module_activity (class_uid 1009) → STIX

Input: OCSF module_activity with `module.file.path`, `module.file.hashes`,
`actor.process.*`, `device.uuid`, `time`.

Output:

- `file` SCO for the loaded module (DLL, .so, etc.), with hashes if present.
- `process` SCO for the loading process.
- `x-host` SCO for the device.
- STIX `Relationship` of custom type `loads` from the process to the file.
- One `ObservedData` referencing all of the above.
- Edges as in §4.1.

### 4.9 OCSF account_change (class_uid 3005) → STIX

Input: OCSF account_change with `user.*` (target), `actor.user.*` (initiator),
`activity_id` (PASSWORD_RESET, ENABLE, DISABLE, GROUP_ADD, GROUP_REMOVE,
PRIVILEGE_GRANT, etc.), `group.*` (if applicable), `device.uuid`, `time`.

Output:

- `user-account` SCO for the target user.
- `user-account` SCO for the initiator if present.
- `x-host` SCO for the device if present (often the IdP itself for cloud
  events).
- For group-related activities: STIX `Relationship` of custom type
  `member-of-group` from target user to a `x-group` custom SCO. Identity for
  `x-group`: `(directory_ref.value, group_name)` where `directory_ref` is
  the AD/Entra/Okta tenant identifier.
- One `ObservedData` referencing all of the above. The `activity_id` is
  preserved in custom extension fields. For privilege grants and revocations,
  the privilege name is preserved in extension fields.
- Edges as in §4.1.

The `activity_id` is the high-information field for this class — the agent
loop reasons differently about a password reset vs. a privilege grant. The
normalizer does not split into multiple ObservedData per activity type;
downstream consumers filter on the extension field.

### 4.10 OCSF email_activity (class_uid 4009) → STIX

Input: OCSF email_activity with `email.from`, `email.to[]`, `email.cc[]`,
`email.bcc[]`, `email.subject`, `email.message_uid`,
`email.attachments[]` (each with file fields), `email.urls[]`,
`smtp.delivery.status`, `time`.

Output:

- `email-message` SCO (STIX 2.1 native) with `from_ref`, `to_refs`, `cc_refs`,
  `bcc_refs`, `subject`, `body_multipart` (if available), `is_multipart`,
  and a `message_id` field populated from `email.message_uid`.
- `email-addr` SCO for each address (sender, recipients, cc, bcc).
- `file` SCO for each attachment, with hashes if present.
- `url` SCO for each URL extracted from the message body.
- STIX `Relationship` of native type `contains` from the email-message to
  each attachment file and url.
- One `ObservedData` referencing the email-message and all of its parts.
- Edges as in §4.1.

`email-message` identity follows STIX 2.1: `(message_id, from_ref.value)` if
both are present, else `(from_ref.value, to_refs, subject, date)` as a
fallback. Cross-tool stitching for emails is more reliable than for processes
because `message_id` is RFC-mandated unique.

### 4.11 OCSF email_url_activity (class_uid 4011) → STIX

Input: OCSF email_url_activity with `url.url_string`, `email.message_uid`,
`actor.user.*` (the clicker), `time`, optional `device.uuid`.

Output:

- `url` SCO for the clicked URL.
- `email-message` SCO referenced by `message_uid` if available (the SCO is
  identified deterministically; if the corresponding email-message is in the
  graph, the click stitches; if not, a stub email-message SCO is created
  with just the message_id for later stitching).
- `user-account` SCO for the clicker.
- `x-host` SCO for the device if present.
- STIX `Relationship` of custom type `clicked` from the user-account to the
  url.
- STIX `Relationship` of native type `contains` from the email-message to
  the url, if the message context is available.
- One `ObservedData` referencing all of the above.
- Edges as in §4.1.

### 4.12 OCSF detection_finding (class_uid 2004) → STIX

Detection findings are structurally distinct from the other classes in this
section: they are not passive observations, they are vendor *interpretations*.
A vendor's detection is a claim that something is bad. The normalizer
respects this.

Input: OCSF detection_finding with `finding.title`, `finding.uid`,
`finding.severity`, `finding.confidence`, `finding.types[]` (e.g., MITRE
ATT&CK technique IDs), `evidence.*` (the underlying telemetry the detection
fired on, often as a nested OCSF event of another class), `time`.

Output:

- STIX `Indicator` SCO with `pattern` (vendor-specific or a STIX pattern if
  the detection exposes one), `pattern_type`, `valid_from`, `confidence`
  mapped from `finding.confidence`, `name` from `finding.title`, and
  `indicator_types` from `finding.types[]`.
- STIX `Sighting` SDO linking the indicator to the entities named in the
  detection. `Sighting.confidence` mirrors the detection's confidence.
- If `evidence.*` is a nested OCSF event, it is recursively normalized
  through the appropriate normalizer (e.g., a detection backed by
  process_activity produces all the entities §4.1 would produce, plus the
  Indicator and Sighting on top).
- One `ObservedData` referencing the entities named in the detection,
  separate from the Sighting. This preserves the raw "this entity was seen"
  signal independent of the vendor's interpretation.
- Edges: standard `extracted-from`/`derived-from` for entities and
  ObservedData; `produced-by` from the Indicator and Sighting to a
  capability-layer-emitted Interpretation marker (see below).
- Provenance on the Indicator and Sighting: `derivation_mode = INFERRED`,
  `tool` = the vendor name. This is the **single exception** to the rule
  that capability-layer outputs are `DIRECT` — the vendor's claim is, by
  definition, an inference, just not one made by our agent loop.

The Indicator and Sighting are interpretation-layer artifacts but the
capability layer **does not** emit a synthetic `x-interpretation` to wrap
them. That would violate two invariants: (a) capability §1, "the layer is
pure I/O plus normalization; does not reason; does not produce
x-interpretation records," and (b) persistence.md §2.1 aggregate ownership
— Interpretations live inside the investigation aggregate, and capability
has no legal write path into it.

Instead:

- The Indicator and Sighting are written to the per-tenant STIX object
  store with `derivation_mode = INFERRED`, `provenance.tool = vendor_name`,
  and STIX-standard `created_by_ref` pointing at a per-tenant **vendor
  Identity SDO**. The vendor Identity is itself a deterministic UUIDv5
  within the tenant namespace (computed from the vendor name), auto-created
  on first ingest. No per-tenant "ingestion service owner" config is
  needed — the upstream attribution lives in `created_by_ref` and
  `provenance.tool`.
- The agent loop (or analyst) wraps these in an Interpretation of type
  `extraction` *when an investigation engages with them* — i.e., when the
  Indicator / Sighting is brought into the investigation's scope via
  `MemberAdded` or referenced as evidence. The Interpretation's
  `actor.principal` is the engaging analyst (or the system principal for
  fully-automated paths); `actor.delegate` is the AI agent if AI-driven.
- Vendor Indicators and Sightings sitting in the store **without** a
  produced-by edge to any of our Interpretations are valid — they are
  imported, not produced by reasoning in our system. The
  `provenance.tool = vendor_name` and STIX `created_by_ref` to the vendor
  Identity together preserve the upstream attribution. (See
  domain_model.md INVARIANTS for the system-produced-vs-imported
  distinction.)

The agent loop is responsible for deciding how much weight to give
vendor-emitted Indicators relative to its own reasoning.

### 4.13 Normalization framework

Every normalizer is a pure function `(OcsfEvent) -> NormalizationResult`.
Normalizers are registered by `class_uid`. A default normalizer handles
unrecognized classes by emitting an opaque `ObservedData` with `object_refs`
empty and the OcsfEvent attached via `derived-from` — the LLM can still see the
raw payload, just without typed entities.

Normalizers are versioned. The version is recorded in the ObservedData's
provenance. If a normalizer is improved, prior OcsfEvents can be re-normalized
into new ObservedData; old ObservedData remains valid (immutable in spirit, even
if the model permits mutation). Re-normalization writes new ObservedData and
links them to the same OcsfEvent.

### 4.14 Custom OCSF classes for non-standard tools

Homegrown tools and niche vendors often emit data that doesn't cleanly map to
any standard OCSF class. Two options, in order of preference:

1. **OCSF vendor extension class.** OCSF supports vendor-specific class
   extensions in the 9000+ range. The adapter assigns a stable extension
   class_uid, documents the payload schema, and a corresponding normalizer is
   registered. This is the right path for any internal tool whose data the
   investigation will reason over repeatedly.
2. **Opaque ObservedData fallback.** The default normalizer (§4.4) handles
   unrecognized classes. Acceptable for v0 and for one-off integrations, but
   loses typed-entity stitching — the LLM sees raw payload, not graph nodes.

The choice is per-tool. A custom CMDB integration probably warrants a custom
class; a one-off enrichment script probably doesn't.

---

## 5. Extension Mechanism

### 5.1 Adding a new verb

Three artifacts:

1. A `CapabilityDescriptor` (Java interface implementation) declaring the verb
   name, input schema, output type, and intent description for the LLM.
2. At least one binding in tenant config mapping it to an existing adapter
   operation (or a new one).
3. Optional: a normalizer if the verb returns OCSF classes not yet handled.

The verb appears in `list_capabilities` automatically once the descriptor is
registered and at least one binding exists. The agent loop fetches the
descriptor list at session start and constructs the LLM tool definitions from
it. There is no hard-coded tool list anywhere.

### 5.2 Adding a new tool integration

Four artifacts:

1. An `Adapter` implementation: connects, authenticates, exposes named
   operations, returns raw responses with `class_uid` and `class_name`
   populated. The adapter is responsible for translating the tool's response
   format into OCSF-shaped JSON before handing to the OcsfEvent writer.
2. Adapter config schema (added to the YAML).
3. Bindings in tenant config for whatever verbs the adapter can fulfill.
4. New normalizers only if the adapter emits OCSF classes not yet handled.

The contract: an adapter's job ends at producing a well-formed OCSF event. It
does not produce STIX. That separation is what lets normalizers be reused across
adapters and what makes vendor swap a config change.

### 5.3 SDK shape

Java backend, so:

```java
public interface Adapter {
    String name();
    AdapterClass adapterClass();              // MCP | NATIVE_API | CUSTOM | FIXTURE
    Set<String> supportedOperations();
    AdapterResponse invoke(String operation, Map<String, Object> params);
    HealthStatus health();
}

public interface CapabilityDescriptor {
    String verb();
    InputSchema inputs();
    OutputType output();
    String intent();
}

public interface Normalizer {
    int classUid();
    int version();
    NormalizationResult normalize(OcsfEvent event);
}
```

All three are discovered via Java's `ServiceLoader` so an extension is a JAR
drop, not a code change.

### 5.4 Adapter classes

Adapters fall into four classes. The contract is identical across all of them;
the class is metadata for operators (visible in `list_capabilities` health
output) and a hook for shared infrastructure (e.g., MCP adapters share
connection pooling and protocol handling that native-API adapters don't need).

**MCP adapters.** Wrap an MCP server. The adapter's `invoke` translates a
capability operation to an MCP tool call, awaits the response, and translates
back to OCSF. One MCP adapter instance per MCP server. Preferred where mature
MCP servers exist for the target tool, because the protocol handles auth flows,
schema discovery, and streaming uniformly.

**Native API adapters.** Talk directly to a vendor's REST/GraphQL/gRPC API
using the vendor SDK or a hand-rolled HTTP client. This is how most v0
integrations will look in practice — CrowdStrike Falcon API, Microsoft Graph,
Splunk REST, Okta API. The adapter owns auth, retries, pagination, and the
vendor-to-OCSF translation. More integration code per adapter than MCP, but
fewer assumptions about external server quality.

**Custom adapters.** For homegrown tools, internal services, data lake queries,
file-based sources, Kafka consumers, anything else. Same `Adapter` contract,
arbitrary implementation. A custom adapter for an internal CMDB is a thin REST
client; a custom adapter for a Snowflake-backed data lake is a SQL executor. As
long as it produces OCSF, it fits.

**Fixture adapters.** A special case of custom adapter for v0, replay, and
testing. See §9.

The OCSF-shaping responsibility lives in the adapter regardless of class. That's
the invariant that makes the layer transport-neutral: by the time data crosses
the adapter boundary, it's OCSF, full stop.

---

## 6. Edge Cases and Graceful Degradation

The capability layer's contract with the LLM on degradation is **structured,
not prose-based**. The agent loop branches on the `coverage` enum from
`CapabilityResult`; `degradation_notes` carries human-readable detail but is
never load-bearing for control flow.

### 6.1 Coverage classification

Every `CapabilityResult` carries one of five `Coverage` values:

**`COMPLETE`** — All eligible bindings were invoked and succeeded. The result
represents the verb's full possible coverage in this tenant. An empty result
under `COMPLETE` is meaningful: it is evidence-of-absence within the queried
scope.

**`PARTIAL`** — At least one binding succeeded and at least one failed. Only
applies to fan-out verbs (§3.4) where multiple bindings legitimately
contribute. The agent loop should treat results as incomplete; the
degradation notes name which sources are missing.

**`UNAVAILABLE_TENANT`** — No binding for this verb is configured in this
tenant, or all bindings were rejected as not-applicable to the input
(required template paths missing — see §3.3.4). This is structural and will
not change without config edits or different input. The agent loop should
not retry; it should either route around the verb or escalate to the
analyst.

**`UNAVAILABLE_TRANSIENT`** — Bindings exist and would have been applicable,
but every adapter is currently unhealthy (auth expired, rate-limited,
network unreachable). This is recoverable. The agent loop may retry the
verb later in the same session, or surface to the analyst that the relevant
tool is offline.

**`FAILED`** — Bindings exist, adapters were healthy at call time, but every
attempt failed at the call site (vendor returned errors, schema mismatch,
query timeout). Distinct from transient because the layer cannot tell
whether a retry would succeed. Treated as recoverable but with lower
expectation than transient.

The classification is computed by the resolver from per-binding outcomes:

```
all bindings succeeded             -> COMPLETE
some succeeded, some failed         -> PARTIAL    (fan-out only)
no bindings applicable to input     -> UNAVAILABLE_TENANT
no bindings configured              -> UNAVAILABLE_TENANT
all applicable bindings unhealthy   -> UNAVAILABLE_TRANSIENT
all applicable bindings called and  -> FAILED
  errored at the call site
```

For non-fan-out verbs, "succeeded" means the highest-priority applicable
binding succeeded; lower-priority bindings are not invoked. There is no
`PARTIAL` for non-fan-out verbs — either the chosen binding succeeded
(`COMPLETE`) or fall-through exhausted (`FAILED` or `UNAVAILABLE_*`).

### 6.2 Adapter error classification

Adapters classify every error as one of:

**`RETRY`** — Transient, same call might succeed if repeated. Rate limits,
network blips, vendor 5xx. The resolver does not retry within a single
capability call; it propagates to the resolver for fall-through.

**`FALLTHROUGH`** — This binding cannot service this call, but another might.
Auth scope insufficient, vendor returns "no data for this device,"
schema-version mismatch. The resolver moves to the next priority binding.

**`UNHEALTHY`** — The adapter as a whole is currently unusable. Auth
credentials invalid, vendor API entirely unreachable, certificate expired.
Marks the adapter unhealthy in `health()` until re-tested. The resolver
treats remaining bindings on this adapter as unavailable for the rest of
this call.

**`FATAL`** — Continuing would corrupt state or violate an invariant. Schema
violation in a write path, identity-rule failure, persistence layer
unreachable. Propagated as a thrown exception. `FATAL` errors should be
rare and represent bugs, not operational conditions.

### 6.3 The `list_capabilities` escape hatch

When the agent loop initializes, it calls `list_capabilities` and trims the
LLM tool set to verbs whose tenant configuration would resolve to at least
one currently-healthy binding. The LLM never sees verbs it cannot use.

When `coverage = UNAVAILABLE_TRANSIENT` or `coverage = FAILED` arrives
mid-session, the agent loop may re-call `list_capabilities` to refresh its
view and trim further. `UNAVAILABLE_TENANT` does not warrant re-listing —
tenant config doesn't change mid-session.

### 6.4 Empty-result semantics

An empty `observed_data_refs` list combined with `coverage = COMPLETE` is
evidence-of-absence: the queried tools were healthy, the query ran, and
nothing matched. The agent loop should treat this as a real signal — a
hypothesis predicting activity in this scope is weakened.

An empty `observed_data_refs` combined with any non-COMPLETE coverage means
absence-of-capability: we did not look, or did not look fully. The agent
loop must not draw inferences about whether the underlying activity
occurred.

The distinction within a single COMPLETE result between "filter was too
narrow" and "telemetry was not available for the time window" is left to
prose in `degradation_notes` and to analyst judgment. Both have the same
operational consequence — widen the filter, widen the window, or accept the
negative result — and the LLM does not need a structured signal to navigate
between them.

### 6.5 Optional richer signals from adapters

Adapters whose underlying tools expose richer coverage information (e.g.,
"Falcon sensor was offline for 4 hours of the requested 24-hour window")
**should** surface this in `degradation_notes` when the call otherwise
succeeds (`coverage = COMPLETE`). This is best-effort and not part of the
structural contract; the agent loop must handle its absence. Tools that
don't expose such signals don't get to fake them — silence on coverage
gaps within a window is the default.

---

## 7. Identity Computation

Identity is the most consequential single decision in the normalizer because it
determines whether the same `8.8.8.8` from CrowdStrike and from Splunk produces
the same SCO id (allowing graph stitching) or two distinct ids (fragmenting the
investigation).

### 7.1 Rule

Identity follows STIX 2.1 deterministic UUIDv5 rules with one structural
deviation: identity is **tenant-scoped**. The format is `<type>--<uuidv5>`.
The UUIDv5 is computed over a canonical-form JSON of the SCO's
identity-contributing fields, using a **per-tenant namespace UUID** — not
the global STIX 2.1 namespace `00abedb4-aa42-466c-9c01-fed23315a9b7` and
not a project-wide custom-object namespace.

Each tenant is assigned a fresh namespace UUIDv4 at tenant creation, stored
in the tenant CRUD record (persistence.md §1), and immutable thereafter.
Both standard SCOs (`ipv4-addr`, `domain-name`, `file`, etc.) and custom
SCOs (`x-host`, `x-registry-key`, `x-scheduled-task`, `x-group`) use the
same per-tenant namespace; there is no separate custom-object namespace.

This makes same-value-different-tenant collision impossible: `8.8.8.8` in
tenant A and `8.8.8.8` in tenant B produce different `ipv4-addr--<uuid>`
values. The `IdentityResolver` (§7.4) takes a tenant id as input, looks up
the namespace UUID, and computes the id; it cannot compute a cross-tenant
or "global" id. Cross-tenant indicator sharing, when introduced, will be a
deliberate publish-to-pool action with its own (separate) namespace UUID;
deferred from v0.

**ObservedData id rule.** ObservedData ids are deterministic UUIDv5 within
the tenant namespace, computed from
`(class_uid, time_truncated_to_second, source_tool, content_hash(payload))`.
Two adapters observing the same OCSF event in the same tenant produce the
same ObservedData id, supporting cross-investigation deduplication within
that tenant. Re-normalization with a newer normalizer version produces a
*new* ObservedData with a different id (the version is part of the
provenance; the new id reflects the new interpretation). Random UUIDv4
ObservedData is also permitted for cases where deterministic identity is
undesirable (e.g., one-off opaque enrichment results); the resolver records
which mode was used in provenance.

The deviation from strict STIX 2.1 is documented as a deliberate trade —
STIX is the *vocabulary* for the interpretation layer (domain_model.md
ARCHITECTURAL COMMITMENTS), not the *wire format*. STIX-conformant ids
remain available if the system ever needs to publish to a STIX-conformant
external consumer; that conversion happens at the export boundary, not in
the storage layer.

### 7.2 Per-type identity-contributing fields

These follow STIX 2.1 spec for native SCOs and are documented here for the
custom and composite cases. Three of them — `process`, `email-addr`, and
`user-account` — involve deliberate deviations from strict spec, called out
explicitly below. All identity tuples below describe what enters the
canonical-form JSON; the JSON is then hashed against the per-tenant
namespace UUID per §7.1.

**Standard cases (no deviation):**

- **`ipv4-addr` / `ipv6-addr`**: `value` (the address string, lowercase, no
  leading zeros).
- **`domain-name`**: `value` (FQDN, lowercase, trailing dot stripped, IDN
  punycoded).
- **`url`**: `value` (full URL, scheme lowercased, host lowercased, default
  ports stripped, fragment preserved, query-string keys sorted).
- **`file`**: hashes in priority order — `SHA-256` if present, else `SHA-1`,
  else `MD5`, else `(name, parent_directory_ref.value, size)`. Hash strings
  lowercased.
- **`x-host`** (custom): priority order — `(asset_id_from_cmdb)` if known, else
  `(domain, hostname)` lowercased, else `(mac_address)` lowercased and
  colon-separated, else `(hostname)` alone.
- **`x-registry-key`** (custom): `(host_ref.id, hive, key_path, value_name)`,
  hive and key_path lowercased.
- **`x-scheduled-task`** (custom): `(host_ref.id, name, path)`, name and path
  lowercased.
- **`x-group`** (custom): `(directory_ref.value, group_name)` lowercased.

**Deviation: `process`.** STIX 2.1 specifies no `id_contributing_properties`
for `process`, intentionally — the spec authors made the call that PIDs are
reused across reboots and within uptime windows, the `(host, pid)` tuple isn't
genuinely unique over time, and processes are inherently transient
observations rather than persistent entities. Strict STIX therefore assigns
every `process` SCO a random UUIDv4 and does not stitch across tools.

We deviate. Identity is
`(host_ref.id, pid, created_time_truncated_to_second)`. Cross-tool process
stitching is a load-bearing operation in this product — every multi-tool
investigation pivots on processes constantly, and `get_process_ancestry`,
`x-supports`/`x-refutes` evidence weighting, and the ObservedData cache all
depend on the same process producing the same SCO id across tool calls.
Without deterministic identity, the graph fragments at exactly the layer
analysts reason about most.

Failure modes:
- If `created_time` is unavailable from any tool reporting the process, the
  process is treated as a transient anonymous SCO with a random UUID. This
  matches strict STIX behavior — no stitching, but no false merges either.
- If two tools report the same process with `created_time` values that
  disagree by more than one second, two SCOs are produced for one process —
  a false split. Detectable: the resolver flags overlapping OcsfEvents on the
  same `(host, pid)` within a configurable window via a `Note` for analyst
  review.
- If a PID is reused after reboot at exactly the same one-second bucket, two
  distinct processes collapse to one SCO — a false merge. Vanishingly
  unlikely given clock skew between reboot and process spawn.

The deviation is reversible: switching to strict STIX is a normalizer change
with no domain-model impact.

**Deviation: `email-addr`.** STIX 2.1 follows RFC 5321, which permits the
localpart of an email address to be case-sensitive. We lowercase the localpart
unconditionally for identity computation. The RFC's case-sensitivity provision
is a theoretical property; real-world email infrastructure — SMTP servers,
IdPs, mail security tools, directory services — is uniformly case-insensitive
in practice, and treating `Alice@contoso.com` and `alice@contoso.com` as
distinct entities would fragment investigations across every email-touching
telemetry source. Cross-tool identity stitching is the load-bearing
requirement; the stitching requirement takes precedence over RFC literalism.

Failure mode: a mail system that genuinely treats localpart as case-sensitive
(vanishingly rare in enterprise contexts) would have two distinct mailboxes
collapse to one SCO. We accept this. The deviation is reversible at the
normalizer level if a future deployment context requires it.

Identity rule: `value` (full address with localpart and domain both
lowercased, trailing whitespace stripped).

**Deviation: `user-account`.** Identity is
`(account_login, user_id, account_type)`. Both `account_login` and `user_id`
are lowercased. `account_login` is normalized per type — Windows domain
accounts as `"domain\\user"` lowercased, email-style accounts as the email
address (subject to the email-addr lowercasing rule above), Unix accounts as
the bare username. `account_type` values include `windows-domain`,
`windows-local`, `unix`, `ldap`, `cloud`, etc.

The lowercasing is a deviation from strict STIX, which preserves case in
account_login. Same rationale as email-addr: Windows is case-insensitive in
account names, AD is case-insensitive, Entra is case-insensitive, and Unix —
while case-sensitive in principle — overwhelmingly uses lowercase account
names in enterprise practice. Treating `CONTOSO\Alice` and `contoso\alice` as
different accounts fragments every authentication-touching investigation.

Failure mode: a Unix system with two accounts differing only by case would
have them collapse to one SCO. Operationally indistinguishable from a
misconfiguration in most environments. Reversible at the normalizer level.

Note that `account_type` does **not** lowercase-collapse: an Entra ID account
(`account_type = cloud`) and an AD account (`account_type = windows-domain`)
for the same human are deliberately distinct SCOs even when the
`account_login` matches. They are, in fact, different accounts. Linking them
is an explicit `aliases` edge created by the agent or analyst, never an
implicit identity merge.

### 7.3 Cross-tool stitching: practical implications

All cross-tool stitching is scoped to a single tenant by construction (§7.1):
the same `8.8.8.8` from tenant A's CrowdStrike and tenant A's Splunk produce
the same `ipv4-addr` SCO; the same `8.8.8.8` from tenant B's CrowdStrike
produces a *different* SCO. Stitching cannot leak across tenants.

Within a tenant, two CrowdStrike hosts with the same hostname but different
`device_id`s will stitch into one `x-host` if the CMDB asset id isn't
available — which may be wrong. This is a known limitation. The mitigation is the `aliases` edge from
the domain model: when the resolver detects a likely false stitch (e.g., two
`x-host` SCOs that resolve to the same id but have different `device_id`s in
their backing OcsfEvents), it emits a `Note` flagging the conflict for analyst
review rather than silently overwriting. A human (or future de-aliasing tool)
can split with an explicit `aliases` edge if needed.

For users: an Entra ID `user-account` (account_type `cloud`) and an AD
`user-account` (account_type `windows-domain`) for the same human will *not*
stitch automatically — they have different `account_type`. This is correct.
They are different accounts. The relationship between them, if known, is
expressed with an `aliases` edge created either by an `x-interpretation` of
type `extraction` (when both are extracted from the same enrichment call) or a
later analyst judgment.

### 7.4 Computation location

Identity is computed inside the normalizer, in a dedicated `IdentityResolver`
component. Adapters never compute STIX ids. This is a hard rule: it ensures
that two adapters can produce conflicting raw fields and the normalizer is the
single arbiter of how those become identity. The `IdentityResolver` takes a
tenant id as input, looks up the tenant's namespace UUID (cached), and
computes the deterministic id; it cannot produce a global / cross-tenant id.
The resolver is pure (given the same tenant + inputs, always produces the
same id), deterministic, and stateless; it can be unit-tested exhaustively
against fixtures.

---

## 8. Caching

### 8.1 Two distinct caches

The OcsfEvent immutability invariant lets us cache aggressively at the raw
layer, while ObservedData freshness is bounded by analyst expectations. So
there are two caches with different policies.

**Raw response cache (per adapter, per operation, per parameter set).** Key:
`hash(adapter, operation, normalized_params, tenant_id)`. Value: the raw
response. TTL: configurable per verb in tenant config, default 15 minutes for
telemetry queries, 1 hour for IdP/CMDB context, no TTL for hash lookups (a hash
is a hash). Eviction: LRU by size. Invalidation: explicit only — there is no
automatic invalidation, because the underlying OcsfEvent is immutable by
definition. If the analyst wants fresh data, they pass `bypass_cache: true` on
the capability call (exposed as a param the LLM can set, not a separate verb).

**ObservedData cache (per investigation, per capability call).** Key:
`hash(verb, normalized_params, investigation_id)`. Value: list of ObservedData
ids (just the ids — actual nodes live in the graph store). TTL: bounded by
investigation lifecycle; cleared on investigation conclusion or archive.
Purpose: prevent the agent loop from re-issuing the same
`get_process_ancestry(P)` three times in one session and cluttering the graph
with duplicate ObservedData.

### 8.2 Cache key normalization

`normalized_params` means params after canonicalization: time windows rounded
to a configurable granularity (default 1 minute), entity references resolved to
STIX ids, optional fields with default values made explicit, sort orders
applied consistently. Without normalization,
`{from: "10:00:00.123Z", to: "11:00:00.456Z"}` and
`{to: "11:00:01Z", from: "10:00:00Z"}` would miss the cache despite being the
same intent.

### 8.3 What does NOT get cached

`query_logs` with raw user-supplied query text bypasses both caches by default.
The query text is too high-cardinality and too potentially sensitive to cache
without explicit opt-in. The LLM can opt in by setting `cacheable: true` on the
QuerySpec when it's confident the query is deterministic and side-effect-free.

### 8.4 Cache and replay

Cache is a runtime performance optimization, not part of the persisted state.
Replay (walking the investigation event stream to reconstruct state — see
persistence.md §2.1) bypasses both caches by design. Replayed reads always
hit the immutable `OcsfEvent` rows and the persisted `ObservedData` graph
directly; cache state at original-write time is irrelevant to replay
correctness.

This means:
- Two analysts replaying the same investigation observe identical state,
  regardless of whether the original session had warm or cold caches.
- Cache eviction policy can be tuned freely without affecting historical
  reproducibility.
- The two caches' lifecycle bindings (raw-response TTL; ObservedData cache
  cleared on conclusion/archive) are operational concerns only — they
  don't constrain what was true in the persisted record.

---

## 9. Fixture Layer

### 9.1 What a fixture is

A fixture is a recorded OCSF event with the binding metadata needed to replay
it. Fixtures are stored as JSON files under `fixtures/<scenario>/<event-N>.json`:

```json
{
  "fixture_meta": {
    "scenario": "lateral-movement-via-rdp",
    "matches": {
      "verb": "enumerate_logons",
      "params": { "target.hostname": "WIN-FILE01", "outcome": "SUCCESS" }
    },
    "delay_ms": 50
  },
  "ocsf": {
    "class_uid": 3002,
    "class_name": "Authentication",
    "time": "2026-04-20T14:32:11Z",
    "actor": { "user": { "name": "jdoe", "domain": "CONTOSO" } },
    "dst_endpoint": { "hostname": "WIN-FILE01" },
    "src_endpoint": { "ip": "10.0.4.55" },
    "logon_type": "RemoteInteractive",
    "status": "SUCCESS"
  }
}
```

Fixtures store **OCSF-shaped events**, not raw vendor responses. This is a
deliberate choice. Storing raw vendor JSON would mean fixtures are coupled to
specific adapters and the normalizer is the only thing under test in v0; we'd
have to re-record fixtures every time a vendor changes their API. Storing OCSF
means fixtures exercise the normalizer and the agent loop, which is what we
actually want to test in v0. The downside: the adapter-to-OCSF translation
layer is not exercised by fixtures. That layer needs separate unit tests with
recorded raw vendor responses.

For scenarios where adapter behavior matters (auth flow testing, error
injection, rate-limit handling), a second fixture format stores raw tool
responses (whether MCP or native API). These are scenario-tagged
`raw_response` fixtures and used only by adapter-level tests, not by the agent
loop.

### 9.2 How the resolver picks fixtures

The fixture adapter is a regular `Adapter` implementation with
`adapterClass = FIXTURE`. In tenant config, the v0 setup has:

```yaml
adapters:
  fixture:
    class: fixture
    enabled: true
    scenario: lateral-movement-via-rdp
  crowdstrike_falcon:
    class: native_api
    enabled: false
  defender_xdr:
    class: native_api
    enabled: false

bindings:
  enumerate_logons:
    - adapter: fixture
      operation: replay
      priority: 100
  get_process_ancestry:
    - adapter: fixture
      operation: replay
      priority: 100
  # ... bindings for every verb point to fixture in v0
```

When the resolver invokes the fixture adapter, the adapter loads the active
scenario, finds fixtures whose `matches` block satisfies the incoming params
(with simple wildcard support), waits `delay_ms` (to mimic real latency for UX
testing), and returns the OCSF event. From there, normalization runs unchanged.
The OcsfEvent gets `source_tool = "fixture:lateral-movement-via-rdp"` so it's
traceable but distinguishable from real telemetry.

### 9.3 Mixed mode

Per-binding override of adapter is allowed, so a tenant can run
`get_user_context` against real Entra while running `enumerate_logons` against
fixtures. This matters for development against partial integrations and for
integration tests that want one real connection plus controlled telemetry.

### 9.4 Recording mode

A future enhancement (post-v0): adapters run in `record` mode against real
tools, capture raw responses + the OCSF translation, and emit fixture files.
This closes the loop on regression-testing real customer scenarios without
retaining sensitive tenant data — fixtures get scrubbed and committed to a
corpus. v0 ships with hand-authored fixtures only.

---

## 10. Open Questions and Deferred Decisions

These are deliberate non-decisions for v0; the spec accommodates either
resolution.

The verb catalog will grow. 22 is a v1 number. The extension mechanism (§5) is
the answer to "how do we get to 40?" without bloating the LLM context, because
`list_capabilities` per-tenant trimming means an analyst at a tenant with only
EDR and IdP coverage sees ~12 verbs, not all 40. Walking real v0 scenarios
through the catalog is expected to drive 1-3 catalog changes; doing it now
in the abstract would be overfitting.

The fanout-and-merge semantics for `pivot_on_indicator` need a real merge
strategy beyond content-hash dedup — specifically, when two adapters return the
same sighting with different timestamps, which wins. v0 punts: emit both as
separate ObservedData and let the agent reason. v1 should define a
canonicalization rule.

The provenance `query` field is currently typed as `string`, which is fine for
SIEM searches but loses fidelity for structured queries (KQL, EQL, SPL). v1
should consider a structured `query` representation that survives round-trip
through ObservedData and is searchable.

The `process` SCO identity rule (§7.2) deviates from strict STIX 2.1 by
including `created_time` in the identity tuple. This is a calculated bet that
process start times are reliably available from EDR telemetry; if it turns out
they're not, fallback to anonymous SCOs will fragment the graph. The
email-addr and user-account lowercasing deviations are similarly bets that
real-world enterprise systems are case-insensitive in practice. All three are
worth measuring on real data before declaring stable; all three are
reversible at the normalizer level.

The line between "native API adapter" and "custom adapter" is fuzzy by design.
Both implement the same contract; the distinction is operational (vendor SDK
vs. internal codebase). If this distinction stops carrying its weight,
collapsing to two classes (mcp / non-mcp) is acceptable.

The templating language (§3.3) is deliberately minimal. If real binding
authoring surfaces a recurring need that the function set doesn't cover, the
right move is almost always to extend the adapter (with a registered
function) rather than to extend the templating language. If that becomes
painful at scale — many adapters needing similar functions — promoting a
function from per-adapter to built-in is a non-breaking change.

The Coverage enum (§6) deliberately collapses some distinctions that were
considered and rejected as not load-bearing for agent-loop control flow —
specifically, the distinction between "0 results because filter was too
narrow" and "0 results because telemetry wasn't available for the window."
Both have the same operational consequence (widen and retry, or accept the
negative result) and the agent loop navigates them via prose in
`degradation_notes` and analyst judgment.

The detection_finding normalizer (§4.12) is the single capability-layer path
that produces interpretation-layer artifacts (Indicator, Sighting) with
`derivation_mode = INFERRED`. This breaks the otherwise-clean rule that the
capability layer emits only `DIRECT` observations. It's the right call —
vendor detections genuinely are inferences, just not ours — but it warrants
review if the boundary between observation and interpretation needs to be
re-litigated.

**Action dispatch / write-side adapter contract is deferred to a v0+1
thread.** This spec covers the read side: 22 query verbs, the binding /
resolver / normalizer pipeline, and the `CapabilityResult` envelope. The
write side — the agent-facing `request_action` tool, write-side adapter
operations, the `adapter_request_id` correlation contract that auth.md §6.1
and persistence.md §3 `ActionDispatched` reference, and the action fixtures
that mirror §9 read fixtures — is referenced by the auth and persistence
specs but not designed here. It is the next thread to spawn before code,
not a v0-time omission to paper over. Until it lands, action dispatch in
v0 prototype runs against fixture stubs only.

---

*End of spec.*
