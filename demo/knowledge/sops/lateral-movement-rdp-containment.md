---
title: Lateral Movement via RDP — Containment
author: SOC Runbooks
tags: [lateral-movement, T1021.001, rdp, containment]
recommendation: isolate
source:
  system: demo
  url: demo://sops/lateral-movement-rdp-containment
  version: "1.0"
---
# Lateral Movement via RDP — Containment

Scope: an interactive RDP logon (OCSF `authentication`, logon type 10) from an
internal host that is not a known jump box, followed by process creation on the
destination. Treat as suspected hands-on-keyboard lateral movement (ATT&CK
T1021.001) until proven benign.

## Triage
1. Confirm the source→destination RDP session in the authentication telemetry.
   Note the account and whether it holds local-admin on the destination.
2. Pull process activity on the destination in the 15 minutes after the logon.
   Discovery tooling, credential access, or archive staging escalate severity.
3. Check whether the account authenticated to additional hosts in the same
   window — a fan-out pattern is the strongest lateral-movement signal.

## Containment
- **Isolate the destination host** if hands-on-keyboard activity is confirmed.
  Prefer network isolation over power-off so volatile evidence survives.
- Disable or force-reset the account if it is being used to pivot. Do not reset
  before capturing which hosts it has already reached, or you lose the map.
- Block the source host's RDP egress if the source itself is compromised rather
  than merely a stolen credential's first hop.

## Do not
- Do not reimage the destination before evidence collection — the process tree
  and any dropped tooling are the investigation.
- Do not treat a single logon as benign because the account is privileged;
  privileged accounts are exactly what this technique abuses.
