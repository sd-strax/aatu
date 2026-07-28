# 00 — Architecture

How the reckon VS Code extension is wired end to end. Read this before any other sheet in
`impl-spec/`; everything here is assumed downstream. Tokens live in `../01-design-system.md`,
the design-vs-native surface split in `../06-vscode-surface-map.md`, and the phased sequence in
`../07-build-order.md`. This package adds the engineering layer: process boundaries, state
ownership, concurrency model, and exact API surface.

---

## 0.1 Architectural invariants

These four constraints determine every structural decision below. If an implementation choice
violates one, the choice is wrong — not the invariant.

| # | Invariant | Structural consequence |
|---|---|---|
| **I1** | **The file is the artifact.** `.inv.md` on disk is the record; every UI is a projection of it. | No surface may hold state the file can't reconstruct. There is no session object, no "unsaved investigation." Cold-open days later must restore exactly. |
| **I2** | **One writer.** All `.inv.md` mutations funnel through `InvestigationStore`. | Command handlers, stream handlers, and webviews *request* mutations; they never touch `fs` or `TextEdit` on an investigation file. |
| **I3** | **Everything streams.** Tokens, tool status, and file appends render incrementally. | The host cannot buffer a turn and emit it whole. Backpressure is handled per-event, not per-turn. No surface may block on another surface's render. |
| **I4** | **Nothing executes without explicit approval.** | Approval state is a *file* field, not UI state. A webview reload mid-approval must not lose or auto-advance it. |

**Derived rule (the one most likely to be violated in practice):** the webview is a renderer,
not a model. It may hold ephemeral view state (scroll, composer draft, open/closed disclosure)
but must be able to be destroyed and rebuilt from a host snapshot at any time with no semantic
loss. Anything you'd be sad to lose on reload belongs in the file.

---

## 0.2 Process and trust boundaries

```
╔═ Federation backend ═══════════════════════════════════════════════════╗
║  POST /investigations/:id/turns        → SSE stream of StreamEvent      ║
║  POST /investigations/:id/actions/:aid/execute                          ║
║  POST /investigations/:id/comms                                         ║
║  GET  /tools/health                                                     ║
╚════════════════════════════╤═══════════════════════════════════════════╝
                             │  HTTPS + SSE. Extension host ONLY.
                             │  The webview never talks to the network.
╔═ Extension host (Node) ════╧═══════════════════════════════════════════╗
║                                                                         ║
║   StreamClient ──────► InvestigationStore ◄────── FileWatcher           ║
║        │                    │   ▲                      ▲                ║
║        │                    │   │ mutate()             │ fs events      ║
║        │                    │   └──── CommandRegistry ──┘               ║
║        │                    │                                           ║
║        │              emitChange(id, state, seq)                        ║
║        │                    │                                           ║
║        ▼                    ▼                                           ║
║   ┌─────────────────────────────────────────────────────────┐          ║
║   │  Subscribers — all read-only, all rebuild from state     │          ║
║   │  TreeProvider · StatusBarController · WebviewHost(s)     │          ║
║   │  DecorationController · EntityRegistry                   │          ║
║   └─────────────────────────────────────────────────────────┘          ║
╚════════════════╤══════════════════════════════════╤════════════════════╝
                 │ postMessage (JSON only)           │ vscode.* native API
╔═ Webviews ═════╧══════════════╗   ╔═══════════════╧════════════════════╗
║  Investigation Panel           ║   ║  Tree · status bar · palette ·     ║
║  Enhanced .inv.md preview      ║   ║  toasts · context menus ·          ║
║  (sandboxed, CSP-locked)       ║   ║  gutter decorations                ║
╚════════════════════════════════╝   ╚════════════════════════════════════╝
```

**What may cross each boundary**

| Boundary | Allowed | Forbidden |
|---|---|---|
| backend → host | `StreamEvent` union only (`05-event-contracts.md`) | HTML, anything the host would `innerHTML` |
| host → webview | JSON-serializable messages, each ≤ ~64KB; raw tool JSON sent on demand, not eagerly | `Uri`, `Disposable`, functions, `Buffer`, whole-state broadcasts on every token |
| webview → host | `ui.*` intents (typed union), no side effects implied | direct file paths, shell strings, anything treated as trusted input |
| host → disk | `InvestigationStore` writes only | any other module writing `.inv.md` |

The webview is treated as **untrusted** for the purposes of action execution: an incoming
`ui.approveAction` is a *request*. The host re-validates tier, precondition, and current
action status against file state before dispatching to the backend (I4). A compromised or
buggy webview must not be able to execute a T3 action.

---

## 0.3 State ownership

Exactly one authority per concern. If two modules can answer the same question, one of them is
wrong.

| Concern | Owner | Everyone else |
|---|---|---|
| Investigation content & status | `InvestigationStore` | subscribes |
| Entity identity & cross-investigation index | `EntityRegistry` | queries |
| Backend connection & turn lifecycle | `StreamClient` | subscribes to relayed events |
| Tool health | `ToolHealthService` (polls `/tools/health`) | subscribes |
| View-only ephemera (scroll, draft, disclosure) | the individual webview | nobody |

### The store contract

```ts
interface InvestigationStore {
  get(id: string): InvestigationState | undefined;
  list(): InvestigationSummary[];

  /** The only mutation path. Serialized per-id. Returns the new seq, or throws ValidationError. */
  mutate(id: string, m: Mutation): Promise<number>;

  /** Monotonic per-investigation version. Webviews use it to detect missed events. */
  seq(id: string): number;

  onDidChange: vscode.Event<{ id: string; state: InvestigationState; seq: number; cause: ChangeCause }>;
}

type ChangeCause = 'stream' | 'command' | 'external-edit' | 'reconcile' | 'create';

type Mutation =
  | { k: 'patchFrontmatter'; patch: Partial<Frontmatter> }
  | { k: 'appendReasoning';  entry: ReasoningEntry }
  | { k: 'appendRemediation'; entry: ActionEntry | ExternalWorkEntry }
  | { k: 'setActionStatus';  actionId: string; status: ActionStatus; error?: string; approvedBy?: string }
  | { k: 'setVerdict';       verdict: Verdict; rationale: string }
  | { k: 'setStatus';        status: Status }
  | { k: 'pinEvidence';      finding: string; source: string }
  | { k: 'appendCommsTrail'; extId: string; entry: CommsTrailEntry }
  | { k: 'writeConclusion';  conclusion: Conclusion };
```

Mutations are **coarse and semantic**, not "set field X." That's what lets the store enforce
state-machine preconditions in one place (see `01-file-schema.md` § 1.6) rather than scattering
them across command handlers.

### Fan-out on change

```ts
store.onDidChange(({ id, state, seq, cause }) => {
  treeProvider.refresh(id);                 // cheap: only the affected subtree
  statusBar.update(state);                  // only if id === activeInvestigationId
  decorations.apply(id, state.evidence);    // gutter pins in the raw editor
  for (const wv of webviewHost.viewsFor(id)) wv.post({ t: 'state.changed', seq, cause, state });
});
```

One subscription list, one refresh path. This is what makes "status is correct in all four
places at once" (`../07-build-order.md` cross-cutting acceptance) structurally true rather than
something you have to remember to do.

---

## 0.4 Concurrency model

Four writers can race on one investigation: the stream, a command, an external editor, and a
second webview. Handle it explicitly.

**Per-investigation serialization.** `mutate()` takes an async lock keyed by investigation id.
All mutations for one file are strictly ordered; different files proceed in parallel.

```ts
private locks = new Map<string, Promise<unknown>>();
async mutate(id: string, m: Mutation): Promise<number> {
  const prev = this.locks.get(id) ?? Promise.resolve();
  const run = prev.catch(() => {}).then(() => this.applyLocked(id, m));
  this.locks.set(id, run);
  return run;
}
```

**Read-modify-write against disk, every time.** `applyLocked` re-reads the file rather than
trusting the in-memory copy, so an external edit landing between two AI turns is picked up
instead of clobbered. Cost is one small file read per mutation — acceptable at this write rate.

**Self-write suppression.** Every internal write records `(path, size, mtimeMs)` in a short
TTL set (~500ms). The watcher checks that set and drops matching events, so an internal write
doesn't masquerade as an external edit and trigger a redundant reconcile → change → re-render
loop.

**Debounced disk writes, immediate UI.** During a stream, `appendReasoning` and `text.delta`
arrive faster than you want to hit the disk. Emit to subscribers immediately; coalesce disk
writes on a 250ms trailing debounce, with a forced flush on `step.end`, on window blur, and on
`deactivate()`. **The debounce must never reorder** — flush is FIFO over the queued mutations.

**Ordering guarantee for the webview.** Every host→webview message carries `seq`. If a webview
receives `seq` that isn't `lastSeq + 1`, it discards its local model and requests a snapshot
(`ui.resync`). This makes reload, sleep/wake, and dropped-frame cases self-healing rather than
subtly divergent.

---

## 0.5 Lifecycle

**Activation** — `onStartupFinished` plus `workspaceContains:**/*.inv.md`. Do not use `*`.

```ts
export async function activate(ctx: vscode.ExtensionContext) {
  const store = new InvestigationStore(config.investigationsDir);
  await store.hydrate();                    // parse all .inv.md, build in-memory index
  const entities = new EntityRegistry(store);
  await entities.rebuild();                 // UUIDv5 index across all investigations

  const stream = new StreamClient(config.backendUrl, store);
  const health = new ToolHealthService(config.backendUrl);

  ctx.subscriptions.push(
    store, entities, stream, health,
    registerTree(store), registerStatusBar(store, health),
    registerCommands(store, stream, entities),
    registerPanel(ctx, store, stream, entities),
    registerFileEditor(ctx, store, entities),
    registerWatcher(store),
    registerDecorations(store),
  );
}
```

Hydrate cost is the one startup risk: a workspace with hundreds of investigations must not
block activation. Parse frontmatter only during hydrate (cheap, bounded); parse bodies lazily
on first open. Budget: **< 400ms for 500 files**.

**Deactivation** — flush pending writes synchronously, close the SSE connection, dispose
watchers. A dropped write on shutdown is a data-loss bug, not a nicety.

**Webview lifecycle** — `retainContextWhenHidden: true` (losing streamed state on tab switch
is unacceptable), plus `getState`/`setState` for scroll position and composer draft so a full
reload is recoverable. On webview load: webview posts `ui.ready` → host replies
`state.snapshot { state, seq }`. All subsequent deltas are `seq`-checked. Never assume the
webview was alive for events sent before its `ui.ready`.

---

## 0.6 Degradation

Every one of these is a **normal state with a designed appearance**, never a stack trace or a
generic error toast. This is a product requirement, not just resilience hygiene.

| Failure | Behavior |
|---|---|
| Backend unreachable | Panel composer disables with an inline reason + Retry. Existing file content stays fully browsable — reading an investigation must not require the backend. Status bar tools item shows disconnected. |
| SSE drops mid-turn | Auto-reconnect with jittered backoff (1s → 30s cap). On resume, request replay from last received event id; if the backend can't replay, mark the in-flight step `interrupted` in the file rather than silently truncating. |
| Single tool errors / not configured | `coverage: ERROR` / `NOT_CONFIGURED` pill on that tool call. Turn continues. Rendered as *information* — never red-alarm styling for "not configured." |
| Invalid `.inv.md` on disk | Last-known-good stays in the UI; banner names the file and the broken rule. reckon does not auto-fix. |
| Two workspace files with the same `id` | Hard error naming both paths. Refuse to hydrate either; ambiguous identity would corrupt the entity index. |
| Action execute request for a stale action status | Host rejects, re-posts authoritative state to the webview. Assume the webview was showing a stale card. |

---

## 0.7 Performance budgets

Treat as acceptance criteria, measured continuously (`08-testing-checkpoints.md`), not aspirations.

| Path | Budget |
|---|---|
| Activation → tree populated | < 400ms @ 500 investigations |
| Query submit → first visible token | **< 3s p50** (from the non-negotiables) |
| `text.delta` → painted | ≤ 1 frame; batch to 1–2 words per rAF tick |
| `mutate()` → all four surfaces consistent | < 50ms (excluding disk flush) |
| Tree refresh | < 16ms for the affected subtree; never refresh the whole tree for one node |
| Frontmatter parse | < 5ms typical, < 20ms for a 200-action file |
| Entity lookup by uuid | O(1) |
| Panel memory after a 60-step investigation | < 120MB; virtualize the reasoning list past ~200 entries |

---

## 0.8 Module layout

```
src/
  extension.ts                    activation only — no logic
  contracts/
    messages.ts                   ui.* + host→webview union. IMPORTED BY BOTH BUNDLES.
    streamEvents.ts               StreamEvent union (05-event-contracts.md)
    schema.ts                     Frontmatter/Action/Entity types (01-file-schema.md)
  store/
    investigationStore.ts         mutate(), lock, debounce, fan-out
    parse.ts                      YAML split, unknown-key preservation
    merge.ts                      deepMergePreserving, appendToSection
    validate.ts                   hard/soft rules, error codes
    stateMachine.ts               status/action/external-work transitions
    entityRegistry.ts             UUIDv5, canonicalization, cross-inv index
    fileWatcher.ts                self-write guard, reconcile
  stream/
    streamClient.ts               SSE, reconnect, replay
    toolHealth.ts
  ui/
    tree/investigationTreeProvider.ts
    statusBar/statusBarController.ts
    decorations/evidenceDecorations.ts
    commands/{lifecycle,evidence,remediation,comms}.ts
  webview/
    panelProvider.ts              WebviewViewProvider + message bridge
    fileEditorProvider.ts         CustomTextEditorProvider
media/
  panel.{html,css,js}             webview bundle
  fonts/                          Open Sans + JetBrains Mono, bundled (no CDN)
```

**Forbidden dependencies** (enforce with a lint rule — these are the edges that rot first):

- `ui/**` and `webview/**` must not import `stream/**`. UI reacts to store changes; it does not
  know a network exists.
- `store/**` must not import `vscode` except for `EventEmitter`/`Disposable`/`FileSystemWatcher`.
  Keeps parse/merge/validate unit-testable headlessly — and they're the parts that need tests most.
- Nothing outside `store/**` may import `fs`.
- `contracts/**` imports nothing. It's the shared vocabulary; a dependency there couples the
  webview bundle to the Node runtime.

---

## 0.9 Sheet index and read order

| Sheet | Covers | Depends on |
|---|---|---|
| `01-file-schema.md` | Field-level schema, canonicalization, validation codes, parse/merge/write, state machines | — |
| `02-tree-view.md` | `TreeDataProvider` node model, grouping, badges, context menus | 01 |
| `03-webview-panel.md` | Panel layout & regions, `CustomTextEditorProvider`, CSP, message bridge | 01, 05 |
| `04-status-bar-commands.md` | Status bar items, command contributions, keybindings, `when` clauses | 01 |
| `05-event-contracts.md` | Backend→host→webview event shapes, ordering, replay | 01 |
| `06-component-library.md` | Buttons, cards, chips, autocomplete, dialogs — classes keyed to tokens | `../01-design-system.md` |
| `07-interaction-flows.md` | Gesture → command → mutation → render, per flow, with code | 01–06 |
| `08-testing-checkpoints.md` | Per-surface verification with no live backend; fixtures; property tests | all |

Implement in `../07-build-order.md` phase order — it front-loads the file layer and the
streaming layer, which is correct: those are the two that are expensive to retrofit.
