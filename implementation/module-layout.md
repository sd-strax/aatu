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

### Paid is layered on OSS, never overlapping

The non-negotiable: paid contributes *implementations* of OSS-defined interfaces and nothing else. It does not reimplement OSS's binary setup, server wiring, supervisor logic, or anything else OSS already owns. To make that architecturally enforceable, OSS exposes the binary's behavior as a `runtime.Run` entry point; both binaries' `main` packages are tiny and differ only in the registry builder they inject.

```go
// aatu/runtime/runtime.go — OSS owns the binary's behavior
package runtime

type ModuleBuilder func(Config) module.Registry

func Run(build ModuleBuilder) error {
    cfg := config.Load()
    reg := build(cfg)
    return supervisor.Start(cfg, reg)  // boots Pg/Temporal/Keycloak, registers worker,
                                       // starts HTTP+WS server with reg installed
}
```

```go
// aatu/cmd/aatu-backend/main.go — OSS binary, three lines
package main

import (
    "github.com/sd-strax/aatu/module"
    "github.com/sd-strax/aatu/runtime"
)

func main() {
    runtime.Run(func(runtime.Config) module.Registry {
        return module.Registry{
            Tenancy:    module.DisabledTenancy{},
            Governance: module.DisabledGovernance{},
        }
    })
}
```

```go
// aatu-enterprise/cmd/aatu-backend/main.go — paid binary, same shape
package main

import (
    "github.com/sd-strax/aatu/module"
    "github.com/sd-strax/aatu/runtime"
    "github.com/sd-strax/aatu-enterprise/governance"
    "github.com/sd-strax/aatu-enterprise/tenancy"
)

func main() {
    runtime.Run(func(cfg runtime.Config) module.Registry {
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
    })
}
```

The only paid-side code that diverges from OSS is the registry builder. Everything else — config loading, supervisor, server, worker registration, lifecycle — lives in OSS's `runtime/` and `supervisor/` packages and is imported by both binaries. There is no paid-side copy of any OSS code.

Other places overlap could creep in, and how it's prevented:

- **Config schema** — defined in `aatu/config/`. Paid imports the schema and its paid sub-tree; never redefines it. The OSS binary recognizes paid keys (logs a warning when they're set), so the schema can't drift.
- **Test helpers** — `aatu/internal/testutil/` is the canonical place for engine-level helpers; paid imports them. (`internal/` would normally block external imports, but the paid repo can use `// +build paidtest` tags or move shared helpers out of `internal/` if the need arises. Defer until it does.)
- **Server hooks / middleware** — the registry is the *only* injection surface. If paid needs to install middleware, it goes through a `module.Middleware()` method on the relevant module interface, not through paid touching OSS's server code.
- **Supervisor / lifecycle** — OSS owns. Paid modules participate via `Start(ctx)` / `Stop(ctx)` methods on their interface; OSS's supervisor invokes them.

If a future paid concern doesn't fit through an existing OSS interface, the answer is to *extend the OSS interface* (in a PR to the OSS repo), not to teach paid to reach around it. The repo boundary is the forcing function: paid literally cannot reach around OSS because OSS doesn't import paid.

## Two binaries, same name

Both repos build a binary named `aatu` (and `aatu-backend`). Customers install one or the other:

- **OSS distribution** — install `aatu` from public binary releases / homebrew / brew tap
- **Paid distribution** — install `aatu` from aatu's customer portal (signed artifacts)

The paid binary is a *behavioral superset* of the OSS binary: run it with all `paid.*.enabled: false` and it behaves identically to OSS (same engine, same code paths). This is what makes the honor-system gate at v0–v1 work: paid binary, flag off = OSS behavior; flag on = paid behavior. At v2+ the entitlement check joins the config flag.

The OSS binary *cannot* run paid modules — they aren't compiled in. This is the architectural enforcement: an OSS install genuinely has no paid code on disk.

## Local cross-repo dev workflow

For contributors working across both repos, the canonical local layout is:

```
~/strax/
├── aatu/                                  # public OSS checkout
└── aatu-enterprise/                       # paid checkout (where applicable)
```

A Go workspace file (gitignored from both repos) makes both modules visible at once:

```
go 1.22

use ./aatu
use ./aatu-enterprise
```

This lets you edit both repos in one workspace and test the paid binary against local OSS without going through a published version. For CI, the paid repo's pipeline fetches a pinned OSS version (no workspace; no replace directive).

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

## Why not single-binary + build tags?

An earlier draft considered a single-repo build with two configurations: (A) one binary, runtime config flag activates paid modules; (B) build tags compile paid code in or out. Both were single-repo options. With two repos, both retire:

- There's no longer a single binary that supersets OSS and paid — there are two binaries from two repos.
- There's no longer a build-tag question — paid code isn't in the OSS repo at all.

The remaining architectural question is: "is the paid binary distributed under the same name as the OSS binary?" Yes — both named `aatu`. The paid binary supersets OSS behaviorally (config + entitlement gate paid features), and the binary name shouldn't change as a deployment converts from OSS to paid; the install source does.

## Cross-references

- `design/05-component-architecture.md §13` — open-core packaging; the architectural commitments this implements
- `design/05-component-architecture.md §13.4` — licensing-as-bolt-on; why the seam matters
