# 04 — Comms, Follow-up & Escalation

External work is **active and two-way**: the analyst communicates from the investigation,
replies flow back, stale items get follow-ups, unresponsive items escalate. The `.inv.md`
becomes the complete coordination record.

## 4.1 Mandatory pre-send preview

No message is ever sent without an explicit confirm. This is lighter than T2 approval (no
evidence review, no tier badge) but heavier than silent execution.

**Preview card** — `--selected-border` + 1px ring:
- Header: channel icon (Slack `#e01e5a` tint / email info tint) · *"Slack message to
  #it-operations"* · subject or *"investigation-linked"* · `PREVIEW` pill (indigo)
- Optional template pill
- **Editable body** in a textarea — starts readonly; **Edit** unlocks it
- Follow-up selector: `none / 24h / 48h / 72h`, defaulted by the AI from context
- Buttons: **Send ⏎** (success) / **Edit** / **Cancel**

The AI drafts the content from investigation context. The analyst can always edit or discard.

## 4.2 Comms card (post-send)

| Status | Pill | Border |
|---|---|---|
| `awaiting_reply` | `AWAITING REPLY` warning | default |
| `replied` | `REPLIED` green | `--ent-domain` |
| `followed_up` | `FOLLOWED UP` warning | default |
| `closed` | `CLOSED` muted | opacity .78 |

Body: quoted first message (italic, inset box) · meta lines — sent timestamp, template,
*"Follow-up in **48h** · N sent"*, and the last inbound reply preview in green when present.
Actions: **View thread** · **Follow up now** · **Mark done**.

## 4.3 Inbound replies

**Reply notification card** — green-bordered, reply icon tile:
*"Reply from Mike Torres in #it-operations"*, `Re: <subject>`, `REPLY` pill; the message in a
quote box with a 3px green left border; received timestamp.
Actions: **View in Slack** (deep link) · **Acknowledge** · **Reply**.

Acknowledge records the ack in the comms trail and collapses the actions to `✓ acknowledged`.

**Inline reply composer** — appears in the chat flow: recipient header, prefilled draft
textarea, **Send** / **Cancel**. Sending appends an outbound trail entry and returns the thread
to `awaiting_reply`.

**Noise control** — only replies from the original recipient or anyone @mentioned in the
original message raise notifications. Everything else is visible via "View in Slack" only.

**When the panel isn't open** — VS Code notification *"Reply received on INV-7741 … [Open
investigation]"*, a badge on the tree row, and the reply card waiting at the top of the panel
on next open.

## 4.4 Follow-up

**Prompt card** (warning-bordered, clock icon, `DUE` pill) fires when the interval elapses on an
unresolved item:
*"Sent to #it-operations 48h ago. No reply yet."*
Actions: **Send follow-up** · **Snooze 24h** · **Mark done** — plus **Escalate to @…** when a
policy has triggered.

Send follow-up increments the counter and reopens the preview card with an AI-drafted message
referencing the original and any replies.

**Cadence defaults** (suggestions, never enforced):
| Work item | Default | Rationale |
|---|---|---|
| Host reimage request | 24h | Containment-adjacent, time-sensitive |
| Credential rotation confirmation | 24h | Active compromise, needs verification |
| Manager notification ack | 48h | Important, not blocking remediation |
| Compliance / legal notification | 72h | Longer response cycles |
| Partner org coordination | 72h | Cross-org, slower cadence |
| General ticket follow-up | 48h | Default |

After 3 follow-ups with no reply, the AI proactively suggests escalation or asks how to proceed.
**Never send infinite follow-ups.**

## 4.5 Escalation

Policies live in `.reckon/config.yaml` and are displayed in settings. In v0 they **surface prompts
but never auto-fire** — the analyst always confirms.

Shipped policies:
- `external-work-stale-72h` — external work open >72h with no resolution after 2+ follow-ups →
  escalate to the owner's manager.
- `t3-pending-30min` — T3 action pending second approval >30 min → notify the IR manager.

**Policy callout** inside the follow-up prompt: danger-tinted box, *"⚠ Escalation policy
triggered"* + the rule text in italic.

**Escalation card** (post-escalate) — danger border, flag icon,
*"Escalated: <subject>"*, *"Level 1 · to Sarah Kim (IT Ops manager)"*, `ESCALATED` pill, and meta
showing the policy id and follow-up count. The escalation message references the full comms trail.

## 4.6 Incident channel

`/slack-channel` creates a dedicated channel, posts an investigation summary (verdict, key
entities, actions so far), invites analyst + manager + on-call IR lead, and links it in
frontmatter under `comms.channel`. If a channel for this investigation already exists, **link it
rather than creating a duplicate**.

Renders as a persistent strip below the summary bar:
`#inv-2026-0425-7741 · 3 participants · 12 messages · Open in Slack`, with a subtle Slack-tinted
gradient. All later `/slack` messages default to this channel.

## 4.7 Templates

Markdown files in `.reckon/templates/` with `{{placeholder}}` and `{{#each}}` support, filled from
investigation context. Shipped: `compromised-account-notification`, `reimage-request`,
`phishing-user-alert`, `incident-mgmt-notification`.

They appear in slash autocomplete after `--template ` with one-line descriptions. A filled
template is always shown in the preview and remains editable — templates are accelerators, not
constraints.

## 4.8 Comms slash commands

```
/slack <#channel|@user> "<message>"
/slack-channel [name]
/email <recipient> [--template <name>]
/notify <recipient> [--template <name>]     channel chosen from recipient config
/followup <ext-id> <interval|datetime>
/link-thread <#channel> <thread-ts> "<label>"
```
`/notify` falls back to email when Slack isn't available; if neither is configured, say so and
offer a manual work item.

## 4.9 File output — comms trail

Each comms item renders in `## Remediation` as a timeline entry with an info-colored node:
header `Slack → #it-operations` + `Comms · awaiting reply`, a meta line (channel, status,
follow-up interval and count), then the trail — a left-ruled list where each entry shows a
direction pill (`outbound` info / `inbound` green / `escalated` danger), author, timestamp, and
the quoted preview.

## 4.10 Closure interaction

Closure is **blocked** while any comms thread is `awaiting_reply` with an active follow-up:

> ⚠ Cannot close: 1 comms thread still awaiting reply
> 📨 Slack → #it-operations: reimage request — [Mark done] [Waive]
> [Force close] [Keep open]

The closure auto-prompt's stat row includes comms and external counts alongside actions.
