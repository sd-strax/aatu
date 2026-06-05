# aatu-specific Go patterns

For general Go style, read in this order:

1. **[Google Go Style Guide](https://google.github.io/styleguide/go/)** — canonical. Three parts: Style Guide, Style Decisions, Best Practices.
2. **[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)** — the actual review checklist.
3. **[Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)** — covers things Google leaves out (mutex placement, error wrapping nuances).

This file is **only** for patterns specific to aatu that the public guides don't address. Keep it short; add only when a pattern is repeated three+ times and a future contributor would need it spelled out.

---

## 1. Pure-function + transaction-wrapper layering

Used in `aatu/aggregate/`. Pattern: split "what events does this command produce?" from "how do I atomically persist + project them?"

```go
// command.go — pure, no DB
func applyCommand(env Envelope, cmd Command, currentSeq int64) ([]Event, error)

// handler.go — owns the transaction
func (h *Handler) Handle(ctx context.Context, env Envelope, cmd Command) (Result, error) {
    tx, _ := h.store.db.BeginTx(ctx, nil)
    currentSeq, _ := h.store.LatestSequenceTx(ctx, tx, env.AggregateID)
    events, _ := applyCommand(env, cmd, currentSeq)
    // ... append + project ...
    return Result{...}, tx.Commit()
}
```

**Why this shape:** the pure function is trivially unit-testable without touching Pg (see `TestApplyCommand_*`). The transaction wrapper is itself thin enough that the integration tests cover it without combinatorial explosion. Don't fold them together.

**Where to use:** any command handler in aggregate/ — and any future command handler in other engine packages that follow the same event-sourcing shape.

---

## 2. `supervisor.Component` lifecycle contract

Used by every type registered with `supervisor.Supervisor`. Implementations must follow:

- **`Start(ctx) error` blocks until ready.** Returning nil means "I'm serving traffic." Pg waits for `accept connections` log; Keycloak polls `/health/ready`; Backend binds the listener and probes deps.
- **`Stop(ctx) error` is idempotent.** Multiple calls must return nil. The watcher's restart cycle and Run's shutdown both call Stop; they may race.
- **`Health(ctx) HealthStatus` is safe under concurrent calls.** The watcher polls every 5s; `/status` requests interleave. Hold internal state under a mutex.

**`RestartPolicy` is the supervisor's job, not the Component's.** Components don't self-restart; they just expose Health honestly. The supervisor watches and applies the policy.

See `implementation/supervisor-design.md` for the full pattern document. **New components must read it before being written.**

---

## 3. Two-axis auth chain

Used in `aatu/server/`. Pattern: compose `authz.RequireAuth` (Gate 1) before per-route `authz.RequireRole` or inline equivalents (still Gate 1, narrower).

```go
// Gate 2 (action authorization, CEL-based) is a separate Phase C concern;
// don't muddy Gate 1 routes with action-policy decisions.

api.Handle("/me", authz.RequireAuth(verifier)(http.HandlerFunc(b.handleMe)))
api.Handle("/investigations", authz.RequireAuth(verifier)(
    http.HandlerFunc(b.investigationsCollection),
))
// inside investigationsCollection:
b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.createInvestigation)
```

**Why composed, not unified:** Gate 1 is about "who is this?", Gate 2 is about "given who they are, can they do this specific action?". Conflating them spreads action policy across HTTP handlers; keep action policy in one place (Phase C, the `action/` package).

---

## 4. Dependency injection by connection string + handler

Used in `server.BackendConfig`. Pattern: the server takes deps as connection strings (Pg DSN, Temporal host:port, Keycloak issuer URL) and constructed handler types (`*aggregate.Handler`), not as component pointers.

```go
type BackendConfig struct {
    PgDSN            string
    TemporalHostPort string
    KeycloakIssuer   string
    Handler          *aggregate.Handler
}
```

**Why:** Backend depends on services being reachable, not on the specific components that brought them up. Cheap to repoint at managed deps later (paid self-hosted at scale uses managed Temporal Cloud / external Pg) without changing the supervisor seam.

The supervisor + server packages stay layered: supervisor knows nothing about engine concerns; server imports engine packages but never reaches back into the lifecycle.

---

## 5. Embedded fs.FS for SQL migrations

Used in `aggregate/migrations.go` and `knowledge/migrations.go`. Each engine subpackage owns its own migration directory, embeds it, and exposes a `Migrations() fs.FS` getter.

```go
//go:embed migrations/*.sql
var migrationsFS embed.FS

func Migrations() fs.FS {
    sub, err := fs.Sub(migrationsFS, "migrations")
    if err != nil {
        panic(err) // can't happen at runtime if embed succeeds at compile time
    }
    return sub
}
```

The `supervisor.PostgresConfig.Databases` field takes `[]DatabaseSpec{Name, Migrations fs.FS}`. `cmd/aatu` injects the migrations; the supervisor calls `pgmigrate.Run` after database creation.

**Why this shape:** supervisor stays unaware of what schemas any engine subpackage owns. Adding a new engine subpackage with its own migrations means adding one entry in `cmd/aatu`'s `Databases` slice — no supervisor changes.

---

## 6. Test infrastructure: per-package TestMain with shared Pg

Used in `aggregate/` and `server/`. Pattern: one embedded-postgres per package (different port), shared `testDB` exposed as a package var, `TestMain` does setup + teardown, individual tests `resetTables` between runs.

Important: `flag.Parse()` before `testing.Short()` in TestMain — without it you get `panic: testing: Short called before Parse`.

```go
func TestMain(m *testing.M) {
    flag.Parse()
    if testing.Short() {
        os.Exit(m.Run())
    }
    // ... heavy Pg setup ...
}
```

Use cleanup functions, **not** `defer`, before any `log.Fatalf` / `os.Exit` paths — those skip deferred cleanup. golangci-lint flags this as `gocritic exitAfterDefer`.

---

## When to add to this file

A pattern goes here only if:

1. It's specific to this codebase (not idiomatic Go).
2. It's used in three+ places (or imminently will be).
3. A future contributor would need it spelled out to keep doing it consistently.

Otherwise: leave the convention to inline comments at the use site.
