# Stage 1: Build Go backend
FROM golang:1.26-bookworm AS go-builder
WORKDIR /build
COPY backend/go.mod backend/go.sum ./backend/
RUN cd backend && go mod download
COPY backend/ ./backend/
RUN cd backend && CGO_ENABLED=0 go build -ldflags="-s -w" -o /nexushub ./cmd/api/

# Stage 2: Build frontend
FROM node:20-bookworm-slim AS node-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r nexushub && useradd -r -g nexushub -s /sbin/nologin nexushub
WORKDIR /app
COPY --from=go-builder /nexushub .
COPY --from=node-builder /build/dist ./frontend/dist
COPY migrations/ ./migrations/
RUN chown -R nexushub:nexushub /app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1
USER nexushub
ENTRYPOINT ["./nexushub"]
