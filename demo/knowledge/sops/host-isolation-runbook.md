---
title: Host Isolation Runbook
author: SOC Runbooks
tags: [containment, host-isolation, evidence-preservation]
recommendation: isolate
source:
  system: demo
  url: demo://sops/host-isolation-runbook
  version: "1.0"
---
# Host Isolation Runbook

Scope: the mechanics of isolating a compromised endpoint so investigation can
continue without letting the adversary act. Isolation is reversible; reimaging
is not — reach for it first.

## Preconditions
- The host is confirmed compromised or is actively being used to pivot.
- You have captured what the host has already reached (isolation freezes the
  host, not the knowledge of where the adversary went next).

## Procedure
1. **Network-isolate**, allowing only the management/EDR channel. This preserves
   memory, running processes, and on-disk artifacts for collection.
2. Notify the host owner through an out-of-band channel — never through the
   isolated host, which the adversary may be watching.
3. Collect volatile evidence (process list, network connections, logged-on
   users) before any reboot.

## Reversal
Isolation is a best-effort, reversible control. Lift it only after the host is
confirmed clean or has been rebuilt. Record the reversal on the case so the
audit trail shows the control was deliberately removed, not dropped.

## Do not
- Do not power the host off — you lose memory-resident evidence and any chance
  of attributing the intrusion.
