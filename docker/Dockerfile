# Stage 1: Build Go backend
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
# Three binaries ship in the runtime image:
#   /nexushub       — the API server (default entrypoint)
#   /nexushub-migrate — the migration runner (Helm pre-install hook)
#   /nexushub-seed  — the first-admin seeder (one-shot)
# Sharing one build stage lets them reuse the module download cache.
WORKDIR /build/backend
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub         ./cmd/api/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub-migrate ./cmd/migrate/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub-seed    ./cmd/seed/

# Stage 2: Build frontend
FROM node:25-bookworm-slim AS node-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:bookworm-slim
# curl is needed by HEALTHCHECK below. It's pre-existing in debian's
# package base but not in -slim; without it the check exits 127 and
# the container is reported unhealthy indefinitely.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r nexushub && useradd -r -g nexushub -s /sbin/nologin nexushub
WORKDIR /app
COPY --from=go-builder /nexushub         ./nexushub
COPY --from=go-builder /nexushub-migrate ./nexushub-migrate
COPY --from=go-builder /nexushub-seed    ./nexushub-seed
COPY --from=node-builder /build/dist ./frontend/dist
COPY migrations/ ./migrations/
RUN chown -R nexushub:nexushub /app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1
USER nexushub
ENTRYPOINT ["./nexushub"]
