# Supervisor design

How the bundled-deps supervisor in `aatu/supervisor/` works. Written so a future contributor coming in cold can change supervisor code with confidence.

This doc covers patterns, not API reference. For exact signatures, read `aatu/supervisor/supervisor.go`.

---

## Job

`aatu start` brings up four things on the analyst's laptop:

1. **Postgres** — embedded via `fergusstrange/embedded-postgres`. Two databases: `aatu_main`, `aatu_knowledge`.
2. **Temporal** — dev server via `go.temporal.io/sdk/testsuite.StartDevServer`. SQLite-backed (D15).
3. **Keycloak** — bundled Temurin JRE 17 + Keycloak 26.0.7 Quarkus distribution. Single realm `aatu` with the canonical role set; master-realm admin auto-bootstrapped (D17).
4. **aatu-backend** — in-process Go service. Today a placeholder that validates dep connectivity and serves `/healthz` + `/status`. Phase A.4–A.7 fill in the engine.

`aatu stop` signals a running supervisor. `aatu status` queries `/status`.

---

## Core abstraction: Component

```go
type Component interface {
    Name() string
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Health(ctx context.Context) HealthStatus
}
```

Every managed thing implements this. Subprocess components (`Postgres`, `Temporal`, `Keycloak`) wrap their respective libraries / process spawns. In-process components (`Backend`) host an HTTP server in a goroutine.

**Start must block until ready.** A Component returning nil from Start means "I am serving traffic." For Postgres this is `embedded-postgres.Start()`. For Temporal it's `testsuite.StartDevServer`. For Keycloak it's a manual poll of `/health/ready` after spawning the JVM. For Backend it's "HTTP listener bound."

**Stop must be idempotent** — multiple calls should not error. The Run loop and external signals can both reach it.

**Health must be safe for concurrent calls** — the watcher polls every 5s; `/status` requests may come at any time. Components hold internal state under a mutex.

---

## Supervisor lifecycle

```go
sup := supervisor.New()
sup.Register(pg, supervisor.FatalOnExit)
sup.Register(temp, supervisor.RestartOnExit)
sup.Register(kc, supervisor.RestartOnExit)
sup.Register(backend, supervisor.RestartOnExit)
err := sup.Run(ctx)
```

**`Register` order is start order.** Components start in registration order; Stop runs them in reverse. Backend is always registered last because it depends on the other three being reachable (its Start probes them).

**`Run(ctx)` is the canonical entry point.** It:

1. Calls `Start` on every component in order. On any Start failure, Stop runs in reverse on the components already started, then Run returns the error.
2. Spawns one watcher goroutine per component.
3. Blocks on the run-context done channel.
4. When run-context is cancelled, waits for all watchers to exit, then runs orderly Stop.

`Start` and `Stop` are also exported for tests or for code that wants tighter lifecycle control; `Run` is the normal supervisor invocation.

---

## Watcher pattern

Each watcher goroutine:

```go
for {
    select {
    case <-ctx.Done(): return
    case <-ticker.C:  // 5s default; tests override
    }
    if Health().Ready { consecutiveMisses = 0; continue }
    consecutiveMisses++
    if consecutiveMisses < 2 { continue }   // tolerate single transient blip
    // ... apply RestartPolicy ...
}
```

### Detection

Two consecutive misses (10s default) before declaring unexpected exit. Tunable via `watchConsecutiveMisses`; tests override via `withFastWatcher`.

### Policies

- **`FatalOnExit`** — call `fatalCancel()` on the run-context. Run's `<-ctx.Done()` unblocks; orderly Stop runs; Run returns nil. Used for Postgres (mid-transaction corruption risk on unclean exit).

- **`RestartOnExit`** — call `Stop` then `Start`. Record the restart timestamp. If the rolling 5-minute window contains ≥3 restarts, escalate to fatal-cancel. If the Start call fails, escalate immediately.

### Tuning vars (package private, vars not consts so tests override)

```go
watchInterval          = 5 * time.Second
watchConsecutiveMisses = 2
watchMaxRestarts       = 3
watchRestartWindow     = 5 * time.Minute
```

---

## Two distinct restart triggers (worth knowing)

1. **Watcher-driven restart** — covered above. Detected via Health() polling. Used when a subprocess is killed externally or stops responding to health probes.

2. **In-component restart-via-Stop-Start** — the watcher's restart call is `spec.Stop` then `spec.Start`. This relies on Stop being idempotent (always safe) and Start being repeatable (downloads cached via marker files, realm imports are no-ops on existing realms, etc.).

If a component's Start logic isn't repeatable, the watcher will misbehave on the first restart. Fix it in the component, not the supervisor.

---

## In-process Backend gotcha

Backend has no subprocess to monitor — its Health() reflects only "is my HTTP listener up." The watcher's Health-polling can't distinguish "the backend was intentionally Stop'd" from "the backend crashed."

Resolution: when shutdown is initiated (ctx cancel → fatal-cancel), the run-ctx propagates. Watchers exit on `<-ctx.Done()` BEFORE Stop is called. So Backend's Stop transitions through "started → not started" only after watchers have already exited; no false-positive restart.

This is why `Run` does `wg.Wait()` before `Stop`.

---

## Air-gap pattern

Three of the four components download artifacts on first run (Pg via embedded-postgres, Temporal CLI via testsuite, JRE+Keycloak via supervisor.downloadAndExtractTarGz). All three honor "if marker file exists at expected path, skip download" semantics.

`make bundle` runs `aatu start` once against a temp data dir, lets all downloads complete, strips transient state, and tars the result. An air-gap user untars to their `~/.aatu/`, runs `aatu start`, and the supervisor finds every binary already present — zero network calls.

The supervisor code is **path-based, not download-based**. Components check for binaries at known paths; how the binaries arrived (download / `make bundle` tarball / OS package) is a distribution concern, not a supervisor concern.

---

## What each component owns

- **`supervisor.Postgres`** — wraps `embedded-postgres`. Owns: data dir layout (`~/.aatu/pg/{data,runtime}`), port (default 5435), database creation (idempotent), legacy `aatu_temporal` cleanup. Exposes: `DSN(dbname)` for downstream consumers.

- **`supervisor.Temporal`** — wraps `testsuite.DevServer`. Owns: data dir, ports (gRPC 7233, UI 8233), namespace registration. Exposes: `FrontendHostPort()`, `Namespace()`.

- **`supervisor.Keycloak`** — orchestrates the IdP. Owns: JRE download/extract, Keycloak download/extract, realm-file installation, bootstrap-admin (idempotent via marker file at `~/.aatu/keycloak/server/data/h2/.aatu-admin-bootstrapped`), kc.sh subprocess management with SIGTERM-then-SIGKILL fallback. Exposes: `IssuerURL()`.

- **`supervisor.Backend`** — in-process placeholder for the eventual aatu engine. Owns: dependency probes (Pg ping, Temporal CheckHealth, Keycloak OIDC discovery), HTTP server on `:8080` with `/healthz` + `/status`. Will be replaced by real engine code through Phase A.4–A.7.

- **`supervisor.Supervisor`** — owns: registration order, start/stop orchestration, watcher goroutines, RestartPolicy enforcement, health rollup. Does not know what individual components do.

---

## PID file + `aatu stop`

`cmd/aatu start` writes its PID to `$DATA_DIR/supervisor.pid` on entry, removes on exit (defer). `cmd/aatu stop` reads the file, sends SIGTERM, polls for the file to disappear.

Safety: `writePIDFile` reads any existing file and checks if the recorded PID is alive (`Signal(0)` probe). If alive, refuses to overwrite — protects against two supervisors racing on the same data dir. If absent or pointing at a dead PID, overwrites.

---

## Test patterns

`supervisor/supervisor_test.go` has the `fakeComponent` (thread-safe via `mu sync.Mutex`) and the `withFastWatcher` test helper (overrides `watchInterval` from 5s to 50ms). All watcher logic — restart, fatal escalation, restart-budget exhaustion, restart-failure escalation — is unit-tested against `fakeComponent`. Tests run in well under a second.

Slow integration tests (`postgres_test.go`, `temporal_test.go`) cover the real binary lifecycle but are skipped under `-short`.

Backend handler logic (`handleHealthz`, `handleStatus`) is unit-tested via `httptest.NewRecorder` without spinning up a real HTTP server.

Helper code (`downloadAndExtractTarGz`) is tested against an in-memory tar.gz served via `httptest.NewServer`.

---

## Where to extend

Adding a new component:

1. Write a type that implements `Component`.
2. Decide its RestartPolicy: FatalOnExit if uncontrolled exit threatens data integrity; RestartOnExit otherwise.
3. Register it in `cmd/aatu/main.go` in dependency order.
4. If it needs to be reachable by Backend, expose a `DSN()` / `HostPort()` / `URL()` getter and wire it into Backend's config.
5. Add unit tests for any non-trivial Start/Stop/Health logic. Use `withFastWatcher` if you want to assert watcher behavior.

Avoid: storing global state in the component (use struct fields), spawning goroutines without a clean Stop path, blocking Stop on external resources without a context deadline.

---

## See also

- `aatu/design/05-component-architecture.md §3` — runtime topology this implements
- `aatu/implementation/module-layout.md` — the OSS/paid repo split this lives inside
- `aatu-enterprise/decisions.md` D15 (Temporal SQLite vs Pg), D17 (JRE+Keycloak bundling)
- `aatu/init/README.md` — launchd / systemd templates for running the supervisor as a system service
