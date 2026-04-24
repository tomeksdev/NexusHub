#!/usr/bin/env bash
# Back up a NexusHub Postgres database to a timestamped .sql.gz.
#
# Detects the deployment shape automatically:
#   - When docker/docker-compose.prod.yml is running, runs pg_dump
#     inside the postgres container.
#   - Otherwise, expects pg_dump on the host and reads DATABASE_URL
#     from /etc/nexushub/env (bare-metal systemd install).
#
# Usage:
#   scripts/backup.sh [output-dir]
#
# Default output dir: /var/backups/nexushub on bare-metal, ./backups
# when running from a developer checkout.

set -euo pipefail

OUT_DIR="${1:-}"
TS=$(date -u +%Y%m%dT%H%M%SZ)

log() { printf '\033[1;34m[backup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[backup]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ -z "$OUT_DIR" ]]; then
  if [[ -d /var/lib/nexushub ]]; then
    OUT_DIR=/var/backups/nexushub
  else
    OUT_DIR=./backups
  fi
fi
mkdir -p "$OUT_DIR"

# Path-relative to repo root when invoked from anywhere.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.prod.yml"

if [[ -f "$COMPOSE_FILE" ]] \
  && docker compose -f "$COMPOSE_FILE" ps --status=running postgres >/dev/null 2>&1 \
  && [[ $(docker compose -f "$COMPOSE_FILE" ps -q postgres) ]]; then
  # Compose path — we don't need DATABASE_URL on the host, docker
  # exec reaches into the container.
  MODE=compose
else
  MODE=hostPG
  [[ -f /etc/nexushub/env ]] || die "no compose stack running and /etc/nexushub/env missing"
  # shellcheck disable=SC1091
  . /etc/nexushub/env
  [[ -n "${DATABASE_URL:-}" ]] || die "DATABASE_URL not set in /etc/nexushub/env"
  command -v pg_dump >/dev/null 2>&1 || die "pg_dump not found (apt install postgresql-client)"
fi

OUT="$OUT_DIR/nexushub-$TS.sql.gz"
log "writing $OUT (mode=$MODE)"

case "$MODE" in
  compose)
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
      pg_dump -U nexushub --no-owner --no-privileges nexushub \
      | gzip -9 > "$OUT"
    ;;
  hostPG)
    pg_dump "$DATABASE_URL" --no-owner --no-privileges \
      | gzip -9 > "$OUT"
    ;;
esac

# Keep the newest 14 backups by default; operators who want longer
# retention should plumb this into their backup rotation (borg,
# restic, etc.) rather than letting this script grow.
find "$OUT_DIR" -maxdepth 1 -name 'nexushub-*.sql.gz' -printf '%T@ %p\n' \
  | sort -rn | tail -n +15 | cut -d' ' -f2- | xargs -r rm -v

log "done — $(ls -lh "$OUT" | awk '{print $5}') bytes"
