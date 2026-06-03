# Module layout — the OSS / paid repo boundary

The single most leveraged architectural commit. aatu's open-core split is enforced by a **repo boundary**, not a folder boundary: OSS in one public repo, paid modules in one private repo, with the paid repo depending on the OSS repo through a stable module-interface package. Lands in Week 1; everything in Phase A and beyond hangs off it.

## Why a repo-level boundary

Open-core projects with `oss/` and `paid/` folders inside a single public repo (GitLab `ee/`, PostHog `ee/`) are widely cited as licensing-and-optics oddities. The dominant pattern in real open-core projects is two repos:

- Mattermost / Mattermost EE
- Grafana / Grafana Enterprise
- Sentry / getsentry
- HashiCorp Vault (OSS) / Vault Enterprise (historical structure)

Two repos give us:

- A public OSS repo that reads as a *real* OSS commitment, not OSS-with-attached-paid
- A clean licensing story — OSS code under an OSS license, paid code under a commercial license, no in-repo confusion
- Architecturally enforced separation: OSS *cannot* import paid because paid isn't in its import graph

The interface contract works identically in one repo or two. Two repos just enforces it harder.

## The two repos

```
aatu                                       # public — github.com/sd-strax/aatu
├── cmd/
│   ├── aatu/                              # OSS CLI entry
│   └── aatu-backend/                      # OSS backend supervisor entry
├── module/                                # interface package — paid repo implements these
├── aggregate/                             # event-sourced investigation aggregate
├── capability/                            # resolver, adapter runtime, normalizers
├── action/                                # action authorization machinery
├── knowledge/                             # SOPs, summaries, retrieval
├── identity/                              # per-tenant namespace, UUIDv5 resolver
├── authz/                                 # JWT validation, role extraction, two-axis evaluation
├── temporal/                              # worker registration, OSS workflows
├── config/                                # config loader
├── server/                                # HTTP+WS server
├── adapters/                              # first-party adapter binaries
├── internal/                              # truly internal helpers
├── design/                                # specs (existing)
└── go.mod

aatu-enterprise                            # private — github.com/sd-strax/aatu-enterprise
├── cmd/
│   ├── aatu/                              # paid CLI entry (supersets OSS)
│   └── aatu-backend/                      # paid backend supervisor entry
├── tenancy/                               # paid tenancy module implementation
├── governance/                            # paid governance module implementation
├── internal/                              # paid-side internal helpers
└── go.mod                                 # depends on github.com/sd-strax/aatu
```

`aatu-enterprise/go.mod` declares the dependency:

```go
module github.com/sd-strax/aatu-enterprise

go 1.22

require github.com/sd-strax/aatu v0.x.y
```

The OSS repo has no awareness of the paid repo. It defines `module/` and ships.

## The interface seam

`aatu/module/` defines interfaces and disabled-stub implementations. `aatu-enterprise/tenancy/` and `aatu-enterprise/governance/` implement them. OSS code calls *only* through `module/` interfaces — and the import path from OSS to paid does not exist because the paid repo isn't in OSS's import graph.

Sketch (Go pseudocode; refine when implementing):

```go
// aatu/module/tenancy.go — interface OSS depends on
package module

type TenancyModule interface {
    Enabled() bool
    ApplyRLS(ctx context.Context, query string) string
    ResolveTenant(ctx context.Context) (TenantID, error)
    LiftPath() (LiftWorkflow, error)
}

// DisabledTenancy is the OSS-default stub. The OSS binary always uses this;
// the paid binary uses it when paid.tenancy.enabled: false.
type DisabledTenancy struct{}

func (DisabledTenancy) Enabled() bool { return false }
func (DisabledTenancy) ApplyRLS(_ context.Context, q string) string { return q }
func (DisabledTenancy) ResolveTenant(_ context.Context) (TenantID, error) {
    return SingleTenantID, nil
}
func (DisabledTenancy) LiftPath() (LiftWorkflow, error) {
    return nil, ErrModuleDisabled
}
```

In OSS code, calls go through the registry:

```go
// somewhere in aatu/aggregate/
import "github.com/sd-strax/aatu/module"

func (a *Aggregate) load(ctx context.Context, id ID) (*Investigation, error) {
    tenant, _ := module.Tenancy().ResolveTenant(ctx)  // OSS-stub returns SingleTenantID
    rlsClause := module.Tenancy().ApplyRLS(ctx, baseQuery)  // OSS-stub returns baseQuery
    ...
}
```

The OSS aggregate doesn't know whether the tenancy module is real or stub. It just calls the interface.

In `cmd/aatu-backend/main.go` (OSS repo):

```go
import "github.com/sd-strax/aatu/module"

func setupModules(cfg Config) module.Registry {
    return module.Registry{
        Tenancy:    module.DisabledTenancy{},
        Governance: module.DisabledGovernance{},
    }
}
```

In `cmd/aatu-backend/main.go` (paid repo):

```go
import (
    "github.com/sd-strax/aatu/module"
    "github.com/sd-strax/aatu-enterprise/tenancy"
    "github.com/sd-strax/aatu-enterprise/governance"
)

func setupModules(cfg Config) module.Registry {
    reg := module.Registry{
        Tenancy:    module.DisabledTenancy{},
        Governance: module.DisabledGovernance{},
    }

    if cfg.Paid.Tenancy.Enabled {
        reg.Tenancy = tenancy.New(cfg.Paid.Tenancy)
    }
    if cfg.Paid.Governance.Enabled {
        reg.Governance = governance.New(cfg.Paid.Governance)
    }

    return reg
}
```

The two `setupModules` functions diverge only here. Everything else in the binary is unchanged.

## Two binaries, same name

Both repos build a binary named `aatu` (and `aatu-backend`). Customers install one or the other:

- **OSS distribution** — install `aatu` from public binary releases / homebrew / brew tap
- **Paid distribution** — install `aatu` from aatu's customer portal (signed artifacts)

The paid binary is a *behavioral superset* of the OSS binary: run it with all `paid.*.enabled: false` and it behaves identically to OSS (same engine, same code paths). This is what makes the honor-system gate at v0–v1 work: paid binary, flag off = OSS behavior; flag on = paid behavior. At v2+ the entitlement check joins the config flag.

The OSS binary *cannot* run paid modules — they aren't compiled in. This is the architectural enforcement: an OSS install genuinely has no paid code on disk.

## Dev workflow (founder + Claude Code on both repos)

Local layout:

```
~/strax/
├── aatu/                                  # public OSS checkout
└── aatu-enterprise/                       # private paid checkout
```

A Go workspace file at `~/strax/aatu.work` (gitignored from both repos) makes both modules visible at once:

```
go 1.22

use ./aatu
use ./aatu-enterprise
```

This lets Claude Code edit both repos in one workspace and test the paid binary against local OSS without going through a published version. For CI, the paid repo's pipeline fetches a pinned OSS version (no workspace; no replace directive).

The Claude Code workflow setup (per `30-day-plan.md` item 1) needs to know about both checkouts: skills, hooks, and the `/review` command should handle either repo.

## What lives where

Quick rule:

- `aatu` (public): code that is part of the OSS commitment. Documented, supported, public.
- `aatu/internal/`: helpers, utilities, shared infrastructure that isn't a commitment to OSS users.
- `aatu-enterprise/`: paid module implementations + the paid binary wireup.
- `aatu-enterprise/internal/`: paid-side internal helpers.

Examples:

- `aatu/aggregate/` — yes, public OSS commitment for the event-sourcing layer.
- `aatu/internal/pgutil/` — Postgres helpers; not part of the public API.
- `aatu-enterprise/tenancy/` — paid tenancy module implementation.

## What this looks like in PR #1

The Week 1 commits land in two repos.

**`aatu` PR #1:**
- Top-level directory structure as above (mostly empty)
- `module/` with interfaces and disabled-stub implementations
- `cmd/aatu-backend/` with OSS-side wireup
- `cmd/aatu/` with `aatu version` only
- Config loader (recognizes paid keys but the OSS binary logs a warning if they're set — OSS binary has no paid module to wire)
- A single Go test that proves: `module.Tenancy().Enabled() == false` and the disabled stubs return their no-op defaults.

**`aatu-enterprise` PR #1:**
- `tenancy/` and `governance/` skeletons with `Enabled() bool` stubs and a stub return
- `cmd/aatu-backend/` with paid-side wireup
- `cmd/aatu/` with paid-side `aatu version` (reports as paid build)
- `go.mod` depending on local OSS via `replace` directive during dev; CI uses pinned version
- A single integration test that proves: build the paid binary, run with `paid.tenancy.enabled: true`, observe `tenancy module: enabled (stub)`; flip to false, observe `tenancy module: disabled`.

No business logic in either. Just the seam, the wireup, and the proof both binaries behave correctly.

## What about D1 (Option A vs B)?

D1 in `decisions.md` framed the question as "single binary with runtime config" vs "build tags, two artifacts." Both were single-repo options. With two repos, both options retire:

- There's no longer a single binary that supersets OSS and paid — there are two binaries from two repos.
- There's no longer a build-tag question — paid code isn't in the OSS repo at all.

The new architectural question is: "is the paid binary distributed under the same name as the OSS binary?" Recommendation: **yes**, both named `aatu`. The paid binary supersets OSS behaviorally (config + entitlement gate paid features), and the binary name shouldn't change as the customer converts from OSS to paid — they just swap the install source.

D1 is marked superseded in `decisions.md`.

## Cross-references

- `design/05-component-architecture.md §13` — open-core packaging; the architectural commitments this implements
- `design/05-component-architecture.md §13.4` — licensing-as-bolt-on; why the seam matters
- `phase-a-backbone.md §A.1` — Phase A scope that depends on this landing first
- `decisions.md` — D1 retired in favor of the two-repo layout
