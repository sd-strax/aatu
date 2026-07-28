# 03 — Remediation & Containment

Verdict is the **midpoint**. When a non-benign verdict is recorded, status moves to
`VERDICT_REACHED` and the AI immediately proposes a remediation plan in the panel.

## 3.1 Trust tiers

| Tier | Meaning | Gate |
|---|---|---|
| **T0** | Read | none |
| **T1** | Annotate (pins, tickets, notifications) | none / preview only |
| **T2** | Reversible action | single explicit approval |
| **T3** | Irreversible action | typed challenge **+** second approver |

**Tier badge** — pill, 9px/800, `letter-spacing:.04em`, with a 7px swatch:
`T1` info · `T2` warning, square swatch · `T3` danger, swatch rotated 45° (diamond).
Label reads `T2 · Reversible` / `T3 · Irreversible`.

Even though v0 ships T0/T1 only in the backend, **leave the visual and interaction room** —
don't foreclose the action tiers.

## 3.2 Action state machine

```
REQUESTED ──approve──> EXECUTING ──> SUCCEEDED ──reverse──> REVERSED
    │                       └──────> FAILED ──retry──> EXECUTING
    │                                   └──skip──> WAIVED
    ├──reject──> REJECTED
    ├──waive──> WAIVED
    └──timeout──> EXPIRED

T3 only:  REQUESTED ──challenge──> AWAITING_SECOND ──co-sign──> EXECUTING
```

Terminal states: `SUCCEEDED`, `REVERSED`, `WAIVED`, `REJECTED`, `EXPIRED`.

## 3.3 Action card

Border color encodes state: requested → warning · approved/executing → info (executing adds a
1px ring) · succeeded → success · failed → danger · reversed → dashed info ·
rejected/waived/expired → 0.72 opacity.

**Header**: 26px verb icon tile tinted by group (containment danger · eradication warning ·
recovery info · notify green) · title (`Isolate host` + entity chip) with tier badge inline ·
`action.type` in 10px mono · state pill (9px/800; spinner while executing).

**Body by state**

- **REQUESTED (T2)** — Reason row · Evidence chips (amber, clickable → open the cited
  record, `02 §2.8`) · TTL if set · *"Requested by AI · via CrowdStrike EDR"* ·
  buttons **Approve ⏎** (success fill) / **Reject ⎋** / **Modify**.

  **Decision-grade requirements** (every REQUESTED card, both tiers — this is the
  highest-stakes click in the product and the card must answer the decision, not just
  offer the buttons):
  - **Approval window countdown** — the frozen `expires_at` rendered live ("expires in
    14m"), turning warning-colored under 5m. Expiry is lazy engine-side; the countdown is
    the analyst's only warning. On elapse the card flips to the EXPIRED posture (badge,
    zero affordances, "re-request if still needed").
  - **Reversibility class, honestly** — `REVERSIBLE` ("undone by host.unisolate") ·
    `BEST_EFFORT` ("reversal attempted, cannot be verified — treated as permanent") ·
    `IRREVERSIBLE` (danger copy). Frozen at request time; the card states which *before*
    approval, not after.
  - **Escalation reason when tier was escalated** — a T2 action over the blast-radius
    threshold arrives as T3 (engine rule, non-negotiable): the card says why
    ("escalated: 14 targets").
  - **Dispatch route** — which binding/adapter will execute ("via crowdstrike-edr" vs
    "via fixture"): what will *actually happen*, not just what was asked.
- **REQUESTED (T3)** — same, plus a danger-tinted challenge box:
  *"Irreversible action. Type **purge 23 emails** to confirm."* with a mono input.
  Buttons: **Confirm** / **Reject**. Mismatch → shake the border red + toast, never proceed.
- **Needs info** — dashed box: *"Scope: **0 emails (pending email trace)**"* +
  `Run email trace first` link. Approve is withheld until scope resolves.
- **AWAITING_SECOND** — warning strip with spinner:
  *"Awaiting second approval from **ir-oncall** pool · first approval by Maya"*.
- **EXECUTING** — dispatched-to row + 6px progress bar (info) + *"executing against target tool…"*.
- **SUCCEEDED** — *"✓ Completed `<ts>` · <tool> confirmed"*, approver line, duration;
  optional auto-approve badge (*"Auto-approved by policy: …"*). Buttons: **Reverse** (if
  reversible) / **View details**.
- **FAILED** — mono error box (`--bad-bg`), attempted timestamp, buttons **Retry** / **Skip** /
  **Error details**. Failure must also raise a non-blocking toast with Retry.
- **REVERSED** — *"Reversed by a follow-up un-isolation action."* Both the original and the
  reversal stay in the timeline; nothing is deleted.
- **REJECTED / WAIVED / EXPIRED** — the recorded rationale.

## 3.4 Remediation plan block

Posted by the AI right after the verdict. Container: 1px `--selected-border`, radius 10px,
header with an indigo wash.

- Header: *"Proposed Remediation Plan"* + *"N actions · grouped by urgency. T2 (reversible) can
  be batch-approved; T3 always reviewed individually."*
- Groups in fixed order with hairline-flanked labels: **Containment → Eradication → Recovery →
  Notification → External work**.
- Footer: **Approve all T2** (primary) / **Review one by one**.

Canonical plan for the reference scenario (use as fixture shape):
| id | type | target | tier | tool |
|---|---|---|---|---|
| act-001 | `host.isolate` | WIN-FIN-04 | T2 | crowdstrike-edr |
| act-002 | `host.isolate` | WIN-HR-12 | T2 | crowdstrike-edr |
| act-003 | `session.revoke` | jchen@acme.local | T2 | entra-id |
| act-004 | `credential.reset` | jchen@acme.local | T2 | entra-id |
| act-005 | `ip.block` (TTL 24h) | 185.220.101.42 | T2 | axonius |
| act-006 | `email.purge` | phishing emails | **T3** | proofpoint |

Verb registry (icon, group, reverse verb):
```
host.isolate → host.unisolate      containment
session.revoke → session.restore   containment
ip.block → ip.unblock              containment
key.revoke → key.restore           containment
file.quarantine                    containment
credential.reset                   eradication  (no reverse)
email.purge                        eradication  (irreversible, T3)
host.unisolate / ip.unblock        recovery
```

**Approve all T2** executes sequentially, not in parallel — the analyst watches containment land
in order.

## 3.5 Ad-hoc actions

Slash commands (available once `VERDICT_REACHED`+):
```
/isolate <host>              /block <ip|domain> [--ttl 24h]
/revoke <user>               /reset <user>
/purge <email-scope>         /quarantine <file>
/ticket <system> "<title>"   /notify <recipient> [--template]
/waive <action-id> "<reason>"
/plan                        /close [--force "<reason>"]
```
Natural language works too ("isolate the HR host") and produces the same request card.
`/block` without `--ttl` escalates to T3 — an indefinite perimeter block is not reversible-by-default.

## 3.6 Action summary bar

Persistent strip under the panel context bar, visible whenever actions exist.

Collapsed: `Remediation 4/6 · 2/3 comms` · segmented progress bar (success / danger / muted
proportions) · counts by state · chevron · **nearest-expiry cue** when any approval window
is open (`⏳ approve within 9m` — the summary bar is where a batch reviewed slowly learns
it is expiring piecemeal).
Expanded: grouped list — **Actions** then **Comms & external work** — each row with a state icon,
label, and state pill. Clicking a row jumps to it in the file.

Counts must agree with the status bar. Only **resolved** items count toward `N/M` — a `FAILED`
action is not resolved.

## 3.7 External work

Cards for tickets and notifications: 30px icon tile (ticket info / notification green), title,
meta (`owner · system` or `template: …`), and a create/draft button that resolves to a state pill
(`open` / `sent` / `closed`).

## 3.8 File output — `## Remediation`

Same timeline treatment as `## Reasoning`, with node colors by outcome (success green, failure
danger, external info). One entry for the plan proposal, one per action (embedding the action
card), and one per external work item.

Section heading shows `N actions · M external`.

## 3.9 Closure

**Auto-prompt** when every action reaches a terminal state:
success-bordered card, *"All remediation actions resolved"*, stat row (succeeded / waived /
external), and buttons **Close investigation** / **Keep open — more work needed**.

**Preconditions.** Closing is blocked unless: verdict set · at least one evidence pin · all
actions terminal · no comms thread still awaiting reply (see `04`). The conclude dialog shows a
literal checklist with pass/fail rows and disables the confirm button until it passes.
`/close --force "<reason>"` waives outstanding items, recording the reason on each.

**On close** — write `## Conclusion` to the file and set `conclusion_ref`:
- Header: *"Incident closed · verdict malicious"*
- 2×2 stat grid: Verdict · Actions taken (+ waived) · External work · Duration
- Narrative summary (2 paragraphs) with live entity chips: what happened, then what was done.

Status → `CONCLUDED`; status bar shifts from indigo to the muted concluded background.
