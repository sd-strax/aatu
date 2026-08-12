---
title: Credential Theft Triage
author: SOC Runbooks
tags: [credential-access, T1003, T1078, triage]
recommendation: reset-credentials
source:
  system: demo
  url: demo://sops/credential-theft-triage
  version: "1.0"
---
# Credential Theft Triage

Scope: signs that account credentials were captured — LSASS access, credential
dumping tooling (ATT&CK T1003), or a valid account used from an anomalous host
(T1078). Goal is to bound blast radius before rotating secrets.

## Establish blast radius first
1. Enumerate every host and service the account touched since the suspected
   theft. The reset is only as good as this list — a missed pivot host keeps the
   adversary in.
2. Identify any secrets the account could read (service accounts, vaulted keys,
   cloud tokens). Theft of a human account often chains to service credentials.
3. Look for persistence established under the account (scheduled tasks, new
   local accounts, registry run keys) — rotating the password does not remove
   these.

## Response
- Force-reset the account and any credentials it could reach; invalidate active
  sessions and tokens, not just the password.
- Remove persistence found above before closing.
- If a service account is implicated, coordinate the rotation — a blind reset of
  a service account causes an outage and tips off the adversary.

## Grounding
Every containment action must cite the specific evidence (the dump event, the
anomalous logon) that justifies it. An un-grounded reset is noise.
