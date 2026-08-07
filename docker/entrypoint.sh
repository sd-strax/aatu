#!/bin/sh
# Engine container entrypoint (design/05 §12.4): first-run init, then the
# supervisor in the foreground as PID 1 (SIGTERM from `docker stop` triggers
# the orderly shutdown).
#
# `reckon init` is idempotent and non-interactive here: the install secrets
# arrive as environment (the vault path — RECKON_PG_PASSWORD +
# RECKON_KC_PASSWORD, injected at runtime, never persisted). Missing secrets
# fail fast with the message naming them; nothing is ever auto-generated.
set -e
reckon init
exec reckon start
