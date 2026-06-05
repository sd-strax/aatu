#!/usr/bin/env bash
# scripts/build-bundle.sh — produce an air-gap-able reckon distribution tarball
# for the current OS/arch.
#
# Strategy: run `reckon start` once against a temporary data dir so the supervisor
# downloads + extracts every bundled binary (Pg, Temporal CLI, Temurin JRE,
# Keycloak). Then strip transient state (Pg cluster data, Temporal SQLite,
# Keycloak runtime data, logs) so the tarball contains only the binaries +
# the reckon launcher itself + an INSTALL.md. An air-gapped customer untars
# this anywhere, points RECKON_CONFIG at it, and runs `bin/reckon start`.
#
# Run via `make bundle` from the repo root.

set -euo pipefail

OS=$(go env GOOS)
ARCH=$(go env GOARCH)
STAGE="${BUNDLE_STAGE:-/tmp/reckon-bundle-stage}"
OUT="bin/reckon-bundle-${OS}-${ARCH}.tar.gz"

echo "==> Cleaning stage directory: $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "==> Writing temporary bundle config"
TMP_CFG=$(mktemp)
cat > "$TMP_CFG" <<EOF
data:
  dir: $STAGE
postgres:
  port: 5499
temporal:
  frontend_port: 17299
  ui_enabled: false
keycloak:
  http_port: 18599
  management_port: 19599
EOF

echo "==> Priming binaries — running reckon start until ready (may take 1–5 min cold)"
LOGFILE=$(mktemp)
RECKON_CONFIG="$TMP_CFG" ./bin/reckon start > "$LOGFILE" 2>&1 &
SUP_PID=$!

ready=0
for i in $(seq 1 96); do  # up to 8 minutes
    if grep -q "bundled stack ready" "$LOGFILE" 2>/dev/null; then
        echo "    [$((i*5))s] all binaries primed"
        ready=1
        break
    fi
    if grep -q "reckon start: supervisor" "$LOGFILE" 2>/dev/null; then
        break
    fi
    sleep 5
done

if [ $ready -ne 1 ]; then
    echo "ERROR: supervisor failed to reach ready state"
    echo "--- last 30 lines of supervisor log ---"
    tail -30 "$LOGFILE"
    kill -INT "$SUP_PID" 2>/dev/null || true
    wait "$SUP_PID" 2>/dev/null || true
    rm -f "$TMP_CFG" "$LOGFILE"
    exit 1
fi

echo "==> Stopping supervisor"
kill -INT "$SUP_PID"
wait "$SUP_PID" 2>/dev/null || true

echo "==> Stripping transient state"
# Pg cluster data — fresh on first run
rm -rf "$STAGE/pg/data"
# Temporal SQLite — fresh on first run
rm -f "$STAGE/temporal/data.sqlite"
# Keycloak runtime data — fresh on first run
rm -rf "$STAGE/keycloak/data"
# Logs — transient
find "$STAGE" -name "logs" -type d -prune -exec rm -rf {} +

echo "==> Copying reckon binaries"
mkdir -p "$STAGE/bin"
cp bin/reckon bin/reckon-backend "$STAGE/bin/"

echo "==> Writing INSTALL.md"
cat > "$STAGE/INSTALL.md" <<EOF
# reckon air-gap bundle ($OS/$ARCH)

This tarball contains everything reckon needs to run, with no network
calls required. The binaries inside (Postgres, Temporal CLI, Temurin
JRE, Keycloak) were pre-downloaded and pre-extracted at build time.

## Install

Extract somewhere persistent — \`/opt/reckon\` is a typical choice:

    sudo mkdir -p /opt/reckon
    sudo tar -xzf reckon-bundle-${OS}-${ARCH}.tar.gz --strip-components=1 -C /opt/reckon
    sudo chown -R \$(whoami) /opt/reckon

## Configure

Create a config that points \`data.dir\` at the install location:

    mkdir -p ~/.reckon
    cat > ~/.reckon/config.yaml <<CFG
    data:
      dir: /opt/reckon
    CFG

## Run

    RECKON_CONFIG=~/.reckon/config.yaml /opt/reckon/bin/reckon start

The supervisor finds Postgres, Temporal, the JRE, and Keycloak under
\`/opt/reckon/\` instead of downloading them. \`reckon start\` runs with
**zero network calls** — air-gap compatible by construction.

## Verify

    # In another terminal:
    curl http://localhost:9543/health/ready              # Keycloak
    nc -z localhost 7233                                  # Temporal gRPC
    psql "host=localhost port=5435 user=reckon password=reckon dbname=postgres sslmode=disable" -c "\l"
EOF

echo "==> Tarring bundle"
mkdir -p bin
stage_basename=$(basename "$STAGE")
stage_parent=$(dirname "$STAGE")
(cd "$stage_parent" && tar -czf "$(pwd -P)/../$OUT" "$stage_basename" 2>/dev/null \
  || tar -czf "$OLDPWD/$OUT" "$stage_basename")

# Compute the absolute output path for the summary line.
OUT_ABS=$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")
SIZE=$(du -sh "$OUT" | cut -f1)
echo ""
echo "==> Bundle: $OUT_ABS ($SIZE)"
echo ""
echo "    Test extract:"
echo "      mkdir /tmp/reckon-extract && tar -xzf $OUT_ABS -C /tmp/reckon-extract --strip-components=1 && ls /tmp/reckon-extract/bin/"

rm -f "$TMP_CFG" "$LOGFILE"
rm -rf "$STAGE"
