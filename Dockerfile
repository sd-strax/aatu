# The engine container (design/05 §12.4): a single image whose entrypoint is
# the supervisor — Postgres, Temporal, Keycloak, backend, and worker all boot
# inside one container, exactly as on a host. For eval/CI/demos and
# server-leaning installs; the native supervisor remains the analyst default.
#
# The binaries/data split: the distributions are BAKED into the image under
# /opt/reckon (prefetch-runtimes at build time → instant boot, no egress
# needed at runtime), while ALL mutable state lives under the single data root
# — mount ONE volume there and the whole stateful surface is captured.
#
# Run:
#   docker run -d --name reckon \
#     -e RECKON_PG_PASSWORD=... -e RECKON_KC_PASSWORD=... \
#     -v reckon-data:/home/reckon/.reckon \
#     -p 127.0.0.1:8080:8080 -p 127.0.0.1:8543:8543 -p 127.0.0.1:9543:9543 \
#     reckon:dev
#
# Ports publish 1:1 on localhost — the backend's issuer probe and the
# workbench's PKCE redirect bake host-visible localhost URLs, so remapping is
# not supported. Named volumes over bind mounts (§12.4: VM file-sharing
# durability). Secrets are env:// / vault:// in container mode — keychain://
# does not exist here.

# --- build stage --------------------------------------------------------------
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

# --- runtime stage ------------------------------------------------------------
FROM debian:bookworm-slim

# ca-certificates: prefetch downloads (build time) + adapter/vendor egress
# (run time) are all TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root from day one: Postgres refuses to run as root, and the fixed UID
# settles volume ownership across restarts (§12.4). The data root must exist
# in the image, reckon-owned, BEFORE the VOLUME declaration — a fresh named
# volume takes its ownership from the image's directory (copy-up); without
# this it mounts root-owned and the first `reckon init` cannot write.
RUN useradd --create-home --uid 10001 reckon \
    && mkdir -p /opt/reckon /home/reckon/.reckon \
    && chown reckon:reckon /opt/reckon /home/reckon/.reckon

COPY --from=build /src/bin/reckon /src/bin/reckon-backend /usr/local/bin/
COPY --from=build /src/bin/reckon-adapter-okta /src/bin/reckon-adapter-greynoise /usr/local/bin/
COPY --from=build /src/bin/reckon-adapter-crowdstrike-falcon /src/bin/reckon-adapter-crowdstrike-response /usr/local/bin/
COPY --from=build /src/bin/reckon-adapter-servicenow /usr/local/bin/
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/reckon-entrypoint

# The seeded demo scenario resolves fixtures relative to the working directory
# (capability.fixture_root default "fixtures").
COPY --from=build --chown=reckon:reckon /src/fixtures /opt/reckon/fixtures
WORKDIR /opt/reckon

# Bake the distributions (Pg, Temporal CLI, JRE + Keycloak) into the image.
# Runs as the reckon user — the throwaway Pg boot inside prefetch would refuse
# root — and doubles as build-time proof the baked stack starts on this
# platform.
USER reckon
RUN reckon prefetch-runtimes --dir /opt/reckon

# The runtime/data split contract (§12.4): distributions from the image,
# everything mutable under the one volume-backed data root.
ENV RECKON_RUNTIME_DIR=/opt/reckon
VOLUME /home/reckon/.reckon

# backend / keycloak http / keycloak mgmt / temporal frontend / temporal ui
EXPOSE 8080 8543 9543 7233 8233

ENTRYPOINT ["reckon-entrypoint"]
