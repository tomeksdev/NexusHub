#!/usr/bin/env bash
# Restore a NexusHub Postgres database from a pg_dump produced by
# backup.sh. Refuses to run against a non-empty DB without an
# explicit --force — a misdirected restore on a live deployment
# would destroy peer configs and revoke working credentials.
#
# Usage:
#   scripts/restore.sh path/to/nexushub-YYYYMMDDTHHMMSSZ.sql.gz [--force]

set -euo pipefail

FILE="${1:-}"
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
  esac
done

log()  { printf '\033[1;34m[restore]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[restore]\033[0m %s\n' "$*" >&2; exit 1; }
warn() { printf '\033[1;33m[restore]\033[0m %s\n' "$*" >&2; }

[[ -n "$FILE" && -f "$FILE" ]] || die "usage: $0 backup.sql.gz [--force]"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.prod.yml"

if [[ -f "$COMPOSE_FILE" ]] \
  && docker compose -f "$COMPOSE_FILE" ps --status=running postgres >/dev/null 2>&1 \
  && [[ $(docker compose -f "$COMPOSE_FILE" ps -q postgres) ]]; then
  MODE=compose
else
  MODE=hostPG
  [[ -f /etc/nexushub/env ]] || die "no compose stack running and /etc/nexushub/env missing"
  # shellcheck disable=SC1091
  . /etc/nexushub/env
  [[ -n "${DATABASE_URL:-}" ]] || die "DATABASE_URL not set"
  command -v psql >/dev/null 2>&1 || die "psql not found"
fi

# Empty-DB guard. Counts user tables; a fresh restore target has
# zero. Operators overriding this accept they're overwriting state.
count_tables() {
  case "$MODE" in
    compose)
      docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U nexushub -tAc \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
      ;;
    hostPG)
      psql "$DATABASE_URL" -tAc \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
      ;;
  esac
}

tables=$(count_tables | tr -d ' \r\n')
if (( tables > 0 )) && (( FORCE == 0 )); then
  die "target database has $tables tables — re-run with --force to overwrite"
fi

if (( FORCE == 1 )) && (( tables > 0 )); then
  warn "--force set — dropping public schema first"
  case "$MODE" in
    compose)
      docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U nexushub -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
      ;;
    hostPG)
      psql "$DATABASE_URL" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
      ;;
  esac
fi

log "restoring $FILE (mode=$MODE)"
case "$MODE" in
  compose)
    gunzip -c "$FILE" | docker compose -f "$COMPOSE_FILE" exec -T postgres \
      psql -U nexushub -v ON_ERROR_STOP=1 nexushub
    ;;
  hostPG)
    gunzip -c "$FILE" | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
    ;;
esac

log "done"
