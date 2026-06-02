# Stage 1: Build frontend
#
# Runs first because the Go build embeds the SPA bundle via
# //go:embed (see backend/internal/uifs/). Without this stage's
# output copied into backend/internal/uifs/dist/ before `go build`,
# the embedded FS is empty and `/` serves a 503 instead of the
# dashboard.
FROM node:26-bookworm-slim AS node-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.26-bookworm AS go-builder
WORKDIR /build
# backend/go.mod has `replace github.com/tomeksdev/NexusHub/ebpf => ../ebpf`,
# so go mod download needs ebpf/go.mod present too. Copy module manifests
# for both modules first to maximize layer caching, then the sources.
COPY backend/go.mod backend/go.sum ./backend/
COPY ebpf/go.mod ebpf/go.sum ./ebpf/
RUN cd backend && go mod download
COPY backend/ ./backend/
COPY ebpf/ ./ebpf/
# Drop the freshly-built SPA into backend/internal/uifs/dist/ so the
# //go:embed directive in the next step pulls real bytes into the
# binary. Without this the embed prefix only sees the .gitkeep
# marker and the runtime image serves the "frontend bundle not
# included" degraded page at /.
COPY --from=node-builder /build/dist/ ./backend/internal/uifs/dist/
# Three binaries ship in the runtime image:
#   /nexushub       — the API server (default entrypoint)
#   /nexushub-migrate — the migration runner (Helm pre-install hook)
#   /nexushub-seed  — the first-admin seeder (one-shot)
# Sharing one build stage lets them reuse the module download cache.
WORKDIR /build/backend
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub         ./cmd/api/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub-migrate ./cmd/migrate/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub-seed    ./cmd/seed/

# Stage 3: Runtime
#
# distroless/static-debian12:nonroot ships with: ca-certificates, /etc/passwd
# entries for the `nonroot` user (uid 65532), tzdata, and nothing else.
# No shell, no package manager, no curl/wget/wg/ip/iptables. The Go
# binaries are CGO_ENABLED=0 in stage 2 so they don't need libc.
#
# Cuts the bookworm-slim CVE surface (libssh2, libcurl, gnutls, krb5,
# etc. — ~220 CVE alerts on the previous base) down to whatever the
# distroless team ships (today: zero in `static`).
#
# We don't shell out to wireguard-tools / iproute2 / iptables from
# the API process — wgctrl-go uses netlink, the eBPF loader uses
# bpf() syscalls, and rtnetlink covers link/address management.
# Anything that genuinely needs those CLIs would run on the host
# outside this image (systemd unit, k8s init container).
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=go-builder /nexushub         ./nexushub
COPY --from=go-builder /nexushub-migrate ./nexushub-migrate
COPY --from=go-builder /nexushub-seed    ./nexushub-seed
# Also copy the raw dist/ for compose's prod stack — Caddy mounts
# /app/frontend/dist over a named volume and serves the SPA itself
# in the "API + Caddy" topology. The single-container topology
# (docker-compose.yml + the bare-metal install) ignores this copy
# and uses the embedded bundle inside the API binary instead.
COPY --from=node-builder /build/dist ./frontend/dist
COPY migrations/ ./migrations/
EXPOSE 8080
# HEALTHCHECK calls the binary itself with -health. The flag is
# wired in cmd/api/main.go: a single HTTP GET to /api/v1/health
# with a 3s timeout, exit 0 on 2xx else 1. No shell needed — the
# exec-form CMD invokes the binary directly.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/app/nexushub", "-health"]
# `nonroot` is uid 65532 on the distroless base; no chown step is
# needed because the file owners on COPY default to root:root which
# is fine for read-only execution and `nonroot` has read+execute on
# the world-readable copies.
USER nonroot
ENTRYPOINT ["/app/nexushub"]
