# 05 — Data Model & State

## 5.1 Frontmatter schema

The structured layer the extension reads and writes. **Manual analyst edits must be preserved** —
parse, merge, and rewrite rather than regenerating wholesale.

```yaml
id: inv-2026-0425-7741
title: "Suspicious PowerShell on WIN-FIN-04"
status: REMEDIATING          # DRAFT|ACTIVE|PAUSED|VERDICT_REACHED|REMEDIATING|CONCLUDED|ARCHIVED
verdict: malicious           # pending|benign|suspicious|malicious
rationale: "lateral movement via compromised identity…"
verdict_at: 2026-04-25T15:01:00Z
seed:
  type: alert                # alert|ioc|hypothesis|case
  source: crowdstrike-edr
  id: EDR-ALERT-7741
created_at: 2026-04-25T14:32:00Z
updated_at: 2026-04-25T15:22:00Z
conclusion_ref: reports/inv-2026-0425-7741-report.md

entities:
  - type: host               # host|user-account|ipv4-addr|file-hash|domain|email-addr|process|alert
    value: WIN-FIN-04
    role: subject            # subject|suspicious|related|alias
    uuid: e4c1b0a2-9f3d-5e88-b1c4-7a02d9f4e110
  - type: user-account
    value: jchen@acme.local
    role: subject
    uuid: b2a3c4d5-6e7f-5012-a3b4-c5d6e7f80912
    alias_of: john.chen@acme.local

evidence:
  - finding: "Login from ASN 9009 (M247) at 2026-04-24T03:14Z — first seen for this user"
    source: entra-id/enumerate_logons
    pinned_at: 2026-04-25T14:48:00Z

comms:
  channel: "#inv-2026-0425-7741"

remediation:
  actions:
    - id: act-001
      type: host.isolate
      target: WIN-FIN-04
      tier: T2
      reversible: true
      tool: crowdstrike-edr
      status: SUCCEEDED
      reason: "Confirmed compromise — active scheduled task establishing persistence."
      evidence_refs: [EDR-ALERT-7741]
      requested_by: AI
      approved_by: Maya
      completed_at: 2026-04-25T15:04:00Z
      duration_s: 8
      ttl: null
      reverses: null
      error: null
      rationale: null            # set on WAIVED / REJECTED
  external_work:
    - id: ext-001
      type: comms                # comms|ticket|notification
      channel: slack             # slack|email
      target: "#it-operations"
      thread_id: "1714060320.001234"
      subject: "Reimage WIN-FIN-04"
      status: awaiting_reply     # awaiting_reply|replied|followed_up|closed | open (tickets)
      sent_at: 2026-04-25T15:12:00Z
      template: reimage-request
      follow_up:
        interval_hours: 48
        next_at: 2026-04-27T15:12:00Z
        count: 0
      comms_trail:
        - direction: out         # out|in|note
          author: Maya
          timestamp: 2026-04-25T15:12:00Z
          preview: "WIN-FIN-04 is isolated and ready for reimage…"
        - direction: in
          author: Mike Torres
          timestamp: 2026-04-26T09:14:00Z
          preview: "Reimage scheduled for tomorrow morning."
      escalation:
        policy: external-work-stale-72h
        triggered: false
    - id: ext-003
      type: ticket
      system: ServiceNow
      ref: INC0042871
      title: "Reimage WIN-FIN-04"
      owner: IT Operations
      status: open
      created_at: 2026-04-25T15:08:00Z
```

## 5.2 Body sections

Fixed order, all optional except `## Reasoning`:
```
## Reasoning      append-only; each entry = timestamp, author, tool calls, interpretation
## Remediation    plan + one entry per action + external work / comms trails
## Conclusion     written on close
```

Reasoning entry, as it must appear in raw markdown:
```markdown
### 14:41 — Geographic login check [AI]

**Tools called:**
- `entra-id/enumerate_logons` → jchen, last 30 days: 47 logins from 10.0.0.0/8, 2 from 185.220.101.42

**Interpretation:** Two sign-ins from a hosting ASN not previously seen… 📌 *Pinned as evidence.*
```

## 5.3 Runtime state (webview)

```ts
interface InvestigationState {
  id: string; file: string; title: string;
  status: Status; verdict: { disp: Verdict; rationale: string };
  entities: string[];                 // values; resolve via entity registry
  evidence: Evidence[];
  reasoning: ReasoningEntry[];
  hypotheses: { text: string; status: 'open'|'supported'|'refuted'|'superseded' }[];
  actions: Action[];
  externalWork: ExternalWork[];
  commsChannel?: { name: string; participants: number; messages: number };
  conclusion?: Conclusion;
  updated_at: string; conclusion_ref?: string;
}
```

Plus UI-only state: `busy` (locks the composer during a turn), `fileMode` (`preview|raw`),
`pendingPin` (the finding the AI suggests pinning next), `theme`.

## 5.4 Entity registry

Entities are global, not per-investigation. Identity is a **deterministic UUIDv5** over
(type, canonical value), so the same IP always resolves to the same id — that's what powers
"appears in N other investigations".

```ts
interface Entity {
  type: EntityType; value: string; uuid: string;
  role: 'subject'|'suspicious'|'related'|'alias';
  aliasOf?: string;                   // linked, never destructively merged
  appearsIn: { id: string; title: string; status: string }[];
  meta: Record<string, string>;       // os, dept, asn, geo, reputation…
}
```

Normalize before hashing (lowercase hostnames/emails, canonical IP form) so aliases don't
accidentally collapse.

## 5.5 Streaming contract

The panel consumes an incremental stream (SSE or WS). Suggested event shape:

```ts
type StreamEvent =
  | { t: 'step.begin';   stepId: string; time: string; title: string }
  | { t: 'tool.status';  stepId: string; callId: string; tool: string; op: string;
                         status: 'calling'|'received'|'normalizing'|'done'|'error'|'skipped' }
  | { t: 'tool.result';  callId: string; query: object; summary: string;
                         coverage: Coverage; raw: object }
  | { t: 'text.delta';   stepId: string; delta: string }
  | { t: 'table';        stepId: string; table: TableSpec }
  | { t: 'confidence';   stepId: string; label: string; pct: number }
  | { t: 'file.append';  section: 'reasoning'|'remediation'; entry: object }
  | { t: 'action.state'; actionId: string; status: ActionStatus; error?: string }
  | { t: 'comms.event';  extId: string; event: 'sent'|'reply'|'followup_due'|'escalated' }
  | { t: 'step.end';     stepId: string; suggest?: string; pinHint?: PinHint };

type Coverage = 'FULL'|'PARTIAL'|'NOT_AVAILABLE'|'ERROR'|'NOT_CONFIGURED';
```

**Ordering requirements**
1. Tool status transitions arrive before the result — the UI must show `calling → received →
   normalizing → done`, never jump straight to done.
2. Fan-out calls are **concurrent**; each emits independently. A slow tool must not gate the others.
3. `file.append` fires **before** the prose finishes streaming, so the analyst watches the file
   grow while the AI is still talking.
4. `text.delta` is word-granular or finer; the UI batches to 1–2 words per frame.

## 5.6 File ↔ panel sync

- **The file wins.** On divergence, re-read from disk and rebuild panel state.
- Watch `investigations/**/*.inv.md` — external edits (vim, GitHub, vanilla VS Code) must
  reconcile without crashing.
- Analyst edits inside `## Reasoning` are **never** overwritten by a subsequent AI append.
  Append only; treat prior content as immutable.
- Switching editor tabs between `.inv.md` files re-scopes the panel (or prompts). The panel must
  always state which investigation it's bound to.
- Cold restore: reopening days later restores exact state from the file. No session concept.

## 5.7 Federated tools (fixture shape)

```
crowdstrike-edr  CrowdStrike EDR       CS  #e0392f  edr       healthy
entra-id         Microsoft Entra ID    EN  #2b88d8  identity  healthy
splunk           Splunk ES (SIEM)      SP  #65a637  siem      healthy
axonius          Axonius Asset DB      AX  #6f5bf0  asset     healthy
proofpoint       Proofpoint TAP        PP  #3aa14b  email     not_configured
```
Tool logo tiles use the brand color with a 2-letter white abbreviation. Health states:
`healthy` (success, pulsing dot) · `degraded` (warning) · `not_configured` (muted).

Operations referenced by the reference scenario:
`get_alert_detail`, `resolve_entity`, `enumerate_logons`, `get_process_ancestry`,
`search_alerts`, `hosts_touched_by_user`, `search`.
