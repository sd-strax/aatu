# 01 — File Schema & Validation

The `.inv.md` file is the artifact (invariant **I1**). This sheet is the contract
`InvestigationStore` enforces in code: field-level schema, entity canonicalization, validation
with error codes, the parse→merge→write algorithm, and the state machines that gate mutations.

`../05-data-model.md` remains the canonical *shape* reference and the source of the worked
example. This sheet does not restate its YAML — it specifies the rules around it.

---

## 1.1 File anatomy

```
┌─ YAML frontmatter ─── machine-owned, analyst-editable, unknown keys preserved
├─ ## Reasoning ─────── append-only. Analyst edits are immutable to reckon.
├─ ## Remediation ───── plan + one entry per action + external work / comms trails
└─ ## Conclusion ────── written once, on close
```

Requirements that hold at all times, including mid-stream:

- Valid YAML frontmatter delimited by `---` on its own line, first byte of the file.
- Valid CommonMark body that reads sensibly with no extension installed (GitHub-renderable).
- Section order fixed as above. `## Reasoning` exists from creation; the other two appear when
  first needed and are never reordered.
- File is UTF-8, LF line endings, single trailing newline. Normalize CRLF on read; write LF.
- Path: `${reckon.investigationsDir}/<id>.inv.md`. Filename must equal `id` — a mismatch is
  `E107`.

### `schema` field — add this

Not in the original data-model sketch. Add it now so migrations never have to sniff field
presence:

```yaml
schema: 1
```

Read behavior: absent → treat as `1` and write it back on next mutation. Greater than the
build's known version → **refuse to write**, open read-only with a banner ("this investigation
was written by a newer reckon"). Silently downgrading a file is data loss.

---

## 1.2 Frontmatter fields

| Field | Type | Req | Rules |
|---|---|:--:|---|
| `schema` | int | ● | See above. |
| `id` | string | ● | `^inv-\d{4}-\d{4}-\d{4}$` — `inv-<year>-<MMDD>-<seq>`. Unique across workspace (`E106`). Immutable after creation. |
| `title` | string | ● | 1–200 chars, single line. Analyst-editable at any time. |
| `status` | enum | ● | `DRAFT ACTIVE PAUSED VERDICT_REACHED REMEDIATING CONCLUDED ARCHIVED`. Transitions gated by § 1.6. |
| `verdict` | enum | ● | `pending benign suspicious malicious`. Defaults `pending`. |
| `rationale` | string | ◐ | **Required when `verdict != pending`** (`E110`). ≥ 20 chars — a one-word rationale defeats the purpose. |
| `verdict_at` | ISO 8601 | ◐ | Required when `verdict != pending`. Must be ≥ `created_at`. |
| `seed.type` | enum | ● | `alert ioc hypothesis` |
| `seed.source` | string | ● | Tool id (must match a configured connector id, else `W203`). |
| `seed.id` | string | ● | Opaque vendor id. Preserve case. |
| `created_at` | ISO 8601 | ● | Immutable. |
| `updated_at` | ISO 8601 | ● | Set by the store on every mutation. Must be ≥ `created_at`. |
| `conclusion_ref` | path | ○ | Workspace-relative. Written on close. Dangling ref is `W205`, not an error. |
| `entities[]` | list | ● | May be empty in `DRAFT`. See § 1.3. |
| `evidence[]` | list | ● | May be empty pre-verdict. `finding` ≥ 10 chars; `source` as `<tool>/<op>`; `pinned_at` ISO. |
| `comms.channel` | string | ○ | `#`-prefixed. Present once an incident channel is opened. |
| `remediation.actions[]` | list | ○ | Section present once the first action exists. See § 1.4. |
| `remediation.external_work[]` | list | ○ | See § 1.5. |

● required · ◐ conditionally required · ○ optional

**All timestamps are ISO 8601 with explicit UTC `Z`.** No local times, no offsets, no
naked dates. Rendering to local time is a UI concern; storage is unambiguous.

---

## 1.3 Entities and canonical identity

Entity identity is the load-bearing mechanism behind "appears in N other investigations." It
must be deterministic and stable across investigations, machines, and time.

```
uuid = uuidv5(canonicalize(type, value), RECKON_NAMESPACE)
RECKON_NAMESPACE = 'b9f4e2c1-7a3d-5f18-9e6b-2c8d4a1f0e77'   // fixed; never change
```

Changing the namespace or any canonicalization rule **invalidates every stored uuid**. If a rule
must change, bump `schema` and re-derive all uuids on migration — do not mix derivations.

### Canonicalization, per type

| Type | Rule | `value` → canonical input |
|---|---|---|
| `host` | trim, lowercase, strip one trailing `.`. Do **not** strip the domain suffix — `win-fin-04` and `win-fin-04.acme.local` are distinct entities, linked via `alias_of` if needed. | `WIN-FIN-04` → `host:win-fin-04` |
| `user-account` | trim, lowercase. `DOMAIN\user` and `user@domain` are distinct; link with `alias_of`. | `JChen@ACME.local` → `user-account:jchen@acme.local` |
| `ipv4-addr` | parse to 32-bit int, re-emit dotted quad (drops leading zeros, rejects `1.2.3.04` shorthand ambiguity). Unparseable → `E112`. | `010.0.0.5` → `ipv4-addr:10.0.0.5` |
| `file-hash` | trim, lowercase hex, strip `0x`. Length must be 32/40/64 (md5/sha1/sha256) else `E113`. | `A1B2…` → `file-hash:a1b2…` |
| `domain` | trim, lowercase, strip trailing `.`, IDNA `toASCII` (punycode). | `Exämple.COM.` → `domain:xn--exmple-cua.com` |
| `email-addr` | trim, lowercase whole address. (RFC allows case-sensitive local parts; SOC practice does not — documented deliberate simplification.) | `Bob@Corp.com` → `email-addr:bob@corp.com` |
| `process` | image **basename** only, lowercased, extension retained. Command line is metadata, not identity. | `C:\Windows\System32\PowerShell.EXE` → `process:powershell.exe` |
| `alert` | trim only, **case preserved** — vendor ids are opaque and sometimes case-significant. | `EDR-ALERT-7741` → `alert:EDR-ALERT-7741` |

Store the **original** `value` as the analyst saw it; canonicalization feeds the hash only.
Display never shows the canonical form.

### Roles and aliasing

`role`: `subject` (what the investigation is about) · `suspicious` (implicated) ·
`related` (contextual) · `alias` (a linked alternate form).

`alias_of` points at another entity's `value` **in the same file** (`E104` if unresolvable).
Aliasing is **non-destructive and never transitive-collapsing**: `A alias_of B` and
`B alias_of C` is a `W207` warning (flatten in the UI, don't rewrite the file). Two entities
never merge into one record — merging destroys the analyst's observation that two forms
appeared.

---

## 1.4 Actions

```ts
interface Action {
  id: string;                    // ^act-\d{3}$ , unique in file, monotonic, never reused
  type: string;                  // ^[a-z]+\.[a-z_]+$  e.g. host.isolate, identity.revoke_sessions
  target: string;                // must match an entity `value` in this file (E103)
  tier: 'T1' | 'T2' | 'T3';
  reversible: boolean;
  tool: string;                  // configured connector id
  status: ActionStatus;
  reason: string;                // >= 20 chars, analyst-readable justification
  evidence_refs: string[];       // each must resolve to an evidence source or seed.id (E102)
  requested_by: 'AI' | string;
  approved_by?: string;          // required for T2/T3 once past AWAITING_APPROVAL (E111)
  second_approver?: string;      // T3 only, required, must differ from approved_by (E114)
  completed_at?: string;
  duration_s?: number;
  ttl?: string | null;           // ISO instant at which a temporary action self-expires
  reverses?: string | null;      // another action id (E105); set on a reversal action
  error?: string | null;         // required when status FAILED (E115)
  rationale?: string | null;     // required when status WAIVED or REJECTED (E116)
}

type ActionStatus =
  | 'PENDING' | 'AWAITING_APPROVAL' | 'RUNNING'          // non-terminal
  | 'SUCCEEDED' | 'FAILED' | 'WAIVED' | 'REJECTED' | 'REVERSED';  // terminal
```

**Reversal is paired, not destructive.** Reversing `act-004` creates `act-009` with
`reverses: act-004`; `act-004` transitions to `REVERSED` and **retains** its original
`completed_at`, `approved_by`, and outcome. Both entries stay in the file and in
`## Remediation` forever. The audit trail is the point.

**Retry does not create a new action.** A `FAILED` action returns to `AWAITING_APPROVAL`
(re-approval required — the world may have changed), keeping its id, and appends a new attempt
line to its `## Remediation` entry. Attempt count is derived from those lines, not stored.

---

## 1.5 External work

```ts
type ExternalStatus = 'awaiting_reply' | 'replied' | 'followed_up' | 'closed'  // comms
                    | 'open';                                                  // tickets
```

- `id`: `^ext-\d{3}$`, unique in file.
- `type: comms` requires `channel` + `target` + `sent_at`; `type: ticket` requires
  `system` + `ref` + `created_at` (`E117`).
- `follow_up.next_at` must be > `sent_at`. `count` increments on each follow-up sent;
  `next_at` advances by `interval_hours` (default from `reckon.followUp.defaultHours`).
- `comms_trail` is **append-only and chronologically ordered** (`E118` if out of order).
  `direction: in` entries are never authored by reckon — they come from the backend's channel
  integration.
- `escalation.triggered` is set by the host when the policy's threshold passes. In v0 this only
  *surfaces a prompt* — it never auto-sends (`reckon.escalation.enabled` gates surfacing, not
  firing).

**Blocking semantics:** `awaiting_reply` and `followed_up` block closure. `replied` does not —
a reply that needs no action is closed by the analyst acknowledging it.

---

## 1.6 State machines

The store rejects any mutation whose transition isn't listed. Rejection returns a
`ValidationError` naming the rule — the UI surfaces the *reason*, never a bare "invalid."

### Investigation status

```
DRAFT ──────► ACTIVE ──────► VERDICT_REACHED ──────► REMEDIATING ──────► CONCLUDED ──► ARCHIVED
                │  ▲               │                      │                              ▲
                ▼  │               └──────────────────────┴──────────────────────────────┘
              PAUSED                       (direct close when no actions are needed)
```

| Transition | Preconditions |
|---|---|
| `DRAFT → ACTIVE` | ≥ 1 entity with `role: subject`. |
| `ACTIVE ⇄ PAUSED` | none. Pausing mid-turn cancels the in-flight turn and records an `interrupted` reasoning entry. |
| `ACTIVE → VERDICT_REACHED` | `verdict != pending` **and** `rationale` ≥ 20 chars **and** ≥ 1 pinned evidence item (`E120` — a verdict with no evidence is the single most important thing to block). |
| `VERDICT_REACHED → REMEDIATING` | ≥ 1 action exists in `remediation.actions`. |
| `VERDICT_REACHED → CONCLUDED` | allowed only when `remediation` is absent/empty — the "nothing to remediate" path. |
| `REMEDIATING → CONCLUDED` | **every** action terminal **and** no `external_work` in `awaiting_reply`/`followed_up` **and** `## Conclusion` written (`E121`, listing the specific blockers). |
| `CONCLUDED → ARCHIVED` | none. Reversible (`ARCHIVED → CONCLUDED`) — archiving is filing, not deletion. |
| any → `DRAFT` | forbidden (`E122`). |

`verdict` is deliberately orthogonal to `status`: reaching a verdict does **not** close the
investigation (design non-negotiable #6). Setting a verdict while `REMEDIATING` is legal —
verdicts can change on new evidence; the change appends a reasoning entry recording the prior
verdict, and never rewrites history.

### Action status

```
PENDING ──► AWAITING_APPROVAL ──► RUNNING ──► SUCCEEDED ──► REVERSED
                │      │                 └──► FAILED ──┐
                │      └──► REJECTED                    └──► (retry) AWAITING_APPROVAL
                └──► WAIVED
```

- T1 may auto-advance `PENDING → RUNNING` if within `reckon.trustTierCeiling`. T2 and T3 never
  auto-advance (I4).
- `→ RUNNING` requires `approved_by`; T3 additionally requires `second_approver != approved_by`
  and a typed-challenge confirmation recorded by the host.
- `SUCCEEDED → REVERSED` requires `reversible: true` and a paired action with `reverses` set.
- `WAIVED`/`REJECTED` require `rationale`.

---

## 1.7 Validation

Two classes. **Hard = refuse the write and leave disk untouched.** A validation failure must
never produce a partially written file.

### Hard errors

| Code | Rule |
|---|---|
| `E101` | Malformed YAML frontmatter or missing `---` delimiters. |
| `E102` | `evidence_refs` entry doesn't resolve to an evidence `source` or `seed.id`. |
| `E103` | Action `target` doesn't match any entity `value`. |
| `E104` | `alias_of` doesn't resolve to an entity `value` in this file. |
| `E105` | `reverses` doesn't resolve to an action `id`. |
| `E106` | Duplicate `id` across the workspace. |
| `E107` | Filename ≠ `id`. |
| `E108` | Unknown enum value in `status`/`verdict`/entity `type`/`role`/action `tier`/`status`. Never coerce. |
| `E109` | Duplicate `act-` or `ext-` id within the file. |
| `E110` | `verdict != pending` without `rationale` (≥ 20 chars) and `verdict_at`. |
| `E111` | T2/T3 action past `AWAITING_APPROVAL` without `approved_by`. |
| `E112` | Unparseable `ipv4-addr`. |
| `E113` | `file-hash` not 32/40/64 hex chars. |
| `E114` | T3 `second_approver` missing or equal to `approved_by`. |
| `E115` | `status: FAILED` without `error`. |
| `E116` | `status: WAIVED`/`REJECTED` without `rationale`. |
| `E117` | External work missing type-required fields. |
| `E118` | `comms_trail` not chronologically ordered. |
| `E119` | Stored `uuid` ≠ recomputed `uuidv5(canonicalize(type, value))`. Recompute on every parse; never trust the stored value. |
| `E120` | `VERDICT_REACHED` without pinned evidence. |
| `E121` | `CONCLUDED` with non-terminal actions or open comms threads. |
| `E122` | Illegal status transition. |
| `E123` | `schema` newer than this build supports. |

### Soft warnings — surface, don't block

| Code | Rule | Handling |
|---|---|---|
| `W201` | Unknown/extra YAML keys. | **Preserve verbatim on rewrite.** Another tool or analyst may own them. Never strip. |
| `W202` | Body content under an unrecognized `##` heading. | Preserve; render as plain markdown. |
| `W203` | `tool`/`seed.source` isn't a configured connector. | Render the tool tile in a muted "unknown connector" state. |
| `W204` | Malformed reasoning-entry heading. | Best-effort render; flag inline ("reckon can't fully parse this section"). |
| `W205` | Dangling `conclusion_ref`. | Show the link as unresolved. |
| `W206` | `updated_at` older than file mtime. | Correct silently on next write. |
| `W207` | Transitive `alias_of` chain. | Flatten for display; leave the file alone. |
| `W208` | Evidence `source` references an op not in the tool's known op list. | Informational only. |

**Never** a stack trace, never a modal, never a red toast for a `W2xx`.

---

## 1.8 Parse → merge → write

The store never regenerates the file wholesale. Regeneration is how analyst edits die.

```ts
async function applyLocked(id: string, m: Mutation): Promise<number> {
  const raw = normalizeEol(await fs.readFile(path(id), 'utf8'));   // disk, not cache
  const { yamlText, body } = splitFrontmatter(raw);                // E101 if malformed

  const doc = YAML.parseDocument(yamlText);        // AST, not POJO — preserves comments + key order
  const fm = doc.toJS() as Frontmatter;
  const { errors, warnings } = validate(fm, body);
  if (errors.length) throw new ValidationError(errors);            // disk untouched

  const patch = derivePatch(fm, m);                                // includes updated_at
  assertTransitionLegal(fm, patch);                                // § 1.6, E120–E122

  applyPatchToDocument(doc, patch);          // mutate AST in place: known keys only, W201 keys survive
  const newBody = m.k.startsWith('append')
    ? appendToSection(body, sectionFor(m), renderEntry(m))         // never touches bytes above insertion
    : body;

  const out = `---\n${doc.toString()}---\n\n${newBody.trimStart()}`;
  await selfWriteGuard(id, () => fs.writeFile(path(id), ensureTrailingNewline(out), 'utf8'));

  const state = project(fm, patch, newBody);
  return this.emitChange(id, state, warnings, causeFor(m));
}
```

Non-negotiable properties of this path:

1. **YAML AST, not object round-trip.** `parse → object → stringify` destroys comments, key
   order, and quoting style, producing a hostile diff on every AI turn. Use
   `YAML.parseDocument` and mutate nodes. Analysts read these diffs in git.
2. **`appendToSection` is byte-preserving above the insertion point.** Locate the heading by
   exact match, find the end of the last entry in that section, splice. If the section is
   absent, create it in the fixed order of § 1.1. Never re-serialize existing entries.
3. **Analyst edits inside `## Reasoning` are immutable.** reckon appends only. There is no
   mutation that edits or deletes an existing reasoning entry — not "shouldn't," *can't*: no
   `Mutation` variant exists for it.
4. **Atomic write.** Write to `<id>.inv.md.tmp` then `rename` — a crash mid-write must not
   truncate the artifact.
5. **Validate before, not after.** Disk is untouched on any hard error.

### Write scheduling

Immediate to subscribers, debounced to disk: 250ms trailing, coalescing queued mutations in
FIFO order (never reorder). Forced flush on `step.end`, on `onDidChangeWindowState` → blurred,
and in `deactivate()`.

---

## 1.9 Reconcile on external edit

The watcher fires for a change the store didn't originate (self-write guard, `00-architecture.md`
§ 0.4). **The file wins.**

| Disk state | Behavior |
|---|---|
| Valid, `schema` known | Adopt as truth. `emitChange(cause: 'external-edit')`. All surfaces re-render. If a turn is in flight, continue it against the new base — appends still land at the end. |
| Valid, `schema` newer | Read-only mode + banner. Refuse writes (`E123`). |
| Hard error | Keep last-known-good in memory for the UI. Banner names the file and the failing code. Offer `reckon: Reconcile` (re-read) and Open Raw. **Do not auto-fix** — fixing is an analyst action. |
| Deleted | Remove from tree and index. If it was active, panel shows an unbound state. Do not recreate. |
| Renamed | Filename ≠ `id` → `E107` banner offering "rename back" or "update id" (the latter re-keys the entity index). |

Reconcile must survive: vim, `git checkout` of a different branch, GitHub web edits, and a bulk
find-and-replace across the whole `investigations/` folder. None of those may crash the
extension or produce a stuck spinner.

---

## 1.10 Testing

Unit-testable headlessly — `store/**` has no `vscode` dependency beyond `EventEmitter`
(§ 0.8 forbidden dependencies exists precisely to make this true).

**Property tests (highest value per line of test code):**

- *Round-trip:* `parse → write` with a no-op patch produces a **byte-identical** file. This
  single test catches most YAML-mangling regressions.
- *Append-only:* for any mutation sequence, bytes above the final insertion point are unchanged.
- *Determinism:* `uuidv5` is stable across process restarts and platforms; canonicalization is
  idempotent (`canon(canon(x)) === canon(x)`).
- *Atomicity:* injecting a hard error at any point leaves disk byte-identical.
- *Machine totality:* every `(status, mutation)` pair either transitions per § 1.6 or throws —
  no silent no-ops.

**Fixtures:** materialize the reference scenario (`../05-data-model.md` §5.1) as fixtures,
one per status, plus a deliberate-corruption set — one per validation code. Both sets drive
testing and demos; bind them to the shipped OCSF fixture scenario
(`fixtures/lateral-movement-via-rdp/`, `03 §9`) so design walkthroughs and the eval harness
run the same story.
