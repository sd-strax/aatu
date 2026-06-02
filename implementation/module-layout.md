# Module layout — the OSS / paid boundary

The single most leveraged architectural commit. Lays down the seam between OSS and paid modules in code so they fill in cleanly at v2 without touching anything in OSS. Lands in Week 1; everything in Phase A and beyond hangs off it.

## Why a code-level boundary at all

Per `design/05-component-architecture.md §13.4`:
- One Go binary across OSS and paid distributions
- Paid modules ship as separately-compilable Go packages
- Activation is config-driven at v0–v1 (honor system); signed-entitlement check bolts on later in a single PR

The architectural seam exists to make that last point true. If OSS code calls directly into paid code, there's no clean place to gate. If paid code calls into OSS via interfaces OSS defines, the gate goes on the interface implementations.

## Top-level layout

```
aatu/
├── cmd/
│   ├── aatu/                # CLI entry (init, start, stop, status, ...)
│   └── aatu-backend/        # backend supervisor entry
├── oss/                     # OSS engine — always compiled in
│   ├── aggregate/           # event-sourced investigation aggregate
│   ├── capability/          # resolver, adapter runtime, normalizers
│   ├── action/              # action authorization machinery
│   ├── knowledge/           # SOPs, concluded-investigation summaries, retrieval
│   ├── identity/            # per-tenant namespace UUID, UUIDv5 resolver
│   ├── authz/               # JWT validation, role extraction, two-axis evaluation
│   ├── temporal/            # worker registration, OSS workflows
│   ├── module/              # module loader, interfaces paid modules implement
│   ├── config/              # config loader, env, secrets indirection
│   └── server/              # HTTP+WS server
├── paid/
│   ├── tenancy/             # paid tenancy module (multi-tenant operation)
│   └── governance/          # paid governance module (SSO helpers, signoff queues, etc.)
├── adapters/                # first-party adapter binaries (separate processes)
│   ├── fixture/             # fixture adapter (always present)
│   ├── mcp-shim/            # MCP adapter scaffold
│   └── ...                  # native vendor adapters land here (v1+)
├── internal/                # truly internal helpers; no module concerns
└── design/                  # specs (existing)
```

## The interface seam

`oss/module/` defines interfaces; `paid/tenancy/` and `paid/governance/` implement them. OSS calls *only* into `oss/module/` interfaces — never directly into `paid/*`. The loader wires implementations in at startup based on config; if a module is disabled, the OSS-side interface returns a no-op or "not enabled" sentinel.

Sketch (Go pseudocode; refine when implementing):

```go
// oss/module/tenancy.go — interface OSS depends on
package module

type TenancyModule interface {
    // Enabled returns true when the paid tenancy module is loaded and activated.
    Enabled() bool

    // ApplyRLS returns the SQL fragment for tenant-aware queries, or empty
    // string when the module is disabled (single-tenant default).
    ApplyRLS(ctx context.Context, query string) string

    // ResolveTenant returns the tenant context for the current request, or
    // the singleton OSS tenant when disabled.
    ResolveTenant(ctx context.Context) (TenantID, error)

    // LiftPath returns the consolidation lift workflow handle, or
    // ErrModuleDisabled when not loaded.
    LiftPath() (LiftWorkflow, error)
}

type GovernanceModule interface {
    Enabled() bool

    // GovernanceMode returns "lightweight" (OSS default) or "gated".
    GovernanceMode() GovernanceMode

    // SignoffRequired returns true for artifacts that require explicit signoff
    // (only true in gated mode); always false in lightweight mode.
    SignoffRequired(artifactType ArtifactType) bool

    // RoleMappingTemplates returns the federation role-mapping templates UI
    // (populated when governance module is loaded; empty otherwise).
    RoleMappingTemplates() []RoleTemplate
}
```

In `oss/`, code calls `module.Tenancy().Enabled()` to branch, or just calls `module.Tenancy().ApplyRLS(...)` and accepts the no-op return when disabled. Never imports `paid/tenancy`.

In `cmd/aatu-backend/`, the wireup happens once at startup:

```go
func setupModules(cfg Config) module.Registry {
    reg := module.NewRegistry()

    if cfg.Paid.Tenancy.Enabled {
        reg.Tenancy = tenancy.New(cfg.Paid.Tenancy)  // import paid/tenancy
    } else {
        reg.Tenancy = module.DisabledTenancy{}  // OSS-side stub
    }

    if cfg.Paid.Governance.Enabled {
        reg.Governance = governance.New(cfg.Paid.Governance)
    } else {
        reg.Governance = module.DisabledGovernance{}
    }

    return reg
}
```

This is the only place `paid/*` is imported. Everything else in OSS imports `oss/module` only.

## Build configurations

Two reasonable options; pick one in Week 1:

**Option A — single binary, runtime config (recommended at v0–v1).**

All packages compile in; `paid/*` activates via config flag. OSS users running the same binary technically *have* the paid code compiled in but can't activate it without flipping the flag. This is the honor-system gate. At v2+ when licensing lands, the flag check expands to "config flag AND valid signed entitlement file."

Pros: one CI matrix, one release artifact, one set of integration tests. Simple.

Cons: OSS users have paid bytes on disk. Not a security concern (the code path is gated), but some open-source purists find it odd.

**Option B — build tags, two distributions.**

`paid/*` packages tagged `//go:build paid`. OSS builds with no tag — paid code isn't compiled in. Paid builds with `-tags=paid` — full binary.

Pros: clean physical separation. OSS users have only OSS code on disk.

Cons: two CI builds, two release artifacts, paid integration tests run in a separate pipeline.

**Recommendation: Option A through v2 GA, evaluate Option B post-GA if open-source community asks for it.** Simpler operationally; the seam is what matters, not the build artifact split.

## Config schema sketch

```yaml
# ~/.aatu/config.yaml
deployment:
  mode: oss              # oss | paid

# Paid module activation (ignored when deployment.mode == oss)
paid:
  tenancy:
    enabled: false
  governance:
    enabled: false
    mode: lightweight    # lightweight | gated

# everything else unchanged across modes
identity:
  keycloak_issuer: https://keycloak.aatu.dev/realms/aatu
  ...
```

When `deployment.mode: oss`, the `paid:` section is ignored by the loader (with a log warning if `paid.tenancy.enabled: true` is set, to catch misconfigurations).

When `deployment.mode: paid`, the loader instantiates each enabled module. At v0–v1 this is just a config check. At v2+, this is `config check AND entitlement file valid for this customer for this module`.

## What lives in `internal/` vs `oss/`

Quick rule:
- `oss/` — code that is part of the OSS commitment. Documented, supported, public.
- `internal/` — helpers, utilities, shared infrastructure that isn't a commitment we're making to OSS users (and Go's import-restriction enforcement of `internal/` keeps us honest).

Examples:
- `oss/aggregate/` — yes, this is the public OSS commitment for the event-sourcing layer.
- `internal/pgutil/` — Postgres helpers that aren't part of the public API.

## What this looks like in PR #1

The Week 1 commit lands:
- Top-level directory structure as above (mostly empty)
- `oss/module/` with interfaces and disabled-stub implementations
- `cmd/aatu-backend/` with the wireup boilerplate
- `cmd/aatu/` with `aatu version` only
- Config loader that respects `deployment.mode`
- A single Go test that proves: with `mode: oss`, `module.Tenancy().Enabled()` returns false; with `mode: paid, paid.tenancy.enabled: true`, it returns true (and a stub returns "module ready but not implemented").

No business logic. Just the seam, the wireup, and the proof it switches correctly.

## Cross-references

- `design/05-component-architecture.md §13` — open-core packaging, the architectural commitments this implements
- `design/05-component-architecture.md §13.4` — licensing-as-bolt-on, why the seam matters
- `phase-a-backbone.md` — Phase A scope that depends on this landing first
- `decisions.md` — Option A vs B build configuration decision (pending Week 1)
