#!/usr/bin/env bash
# NexusHub bare-metal installer for Debian + Ubuntu.
#
# Installs: postgresql, wireguard-tools, the nexushub-api binary,
# the systemd unit, and a blank /etc/nexushub/env to fill in.
#
# One-liner bootstrap (replace the tag with the release you want):
#   curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
#     | sudo NEXUSHUB_VERSION=v2.0.0 bash
#
# The script is idempotent — re-running it upgrades the binary and
# refreshes the unit without touching /etc/nexushub/env or the
# Postgres database.

set -euo pipefail

NEXUSHUB_VERSION="${NEXUSHUB_VERSION:-latest}"
NEXUSHUB_USER="${NEXUSHUB_USER:-nexushub}"
NEXUSHUB_DB="${NEXUSHUB_DB:-nexushub}"
NEXUSHUB_STATE_DIR="${NEXUSHUB_STATE_DIR:-/var/lib/nexushub}"
NEXUSHUB_LOG_DIR="${NEXUSHUB_LOG_DIR:-/var/log/nexushub}"
NEXUSHUB_CONFIG_DIR="${NEXUSHUB_CONFIG_DIR:-/etc/nexushub}"
NEXUSHUB_BIN="${NEXUSHUB_BIN:-/usr/local/bin/nexushub-api}"
REPO_RAW="https://raw.githubusercontent.com/tomeksdev/NexusHub"
REPO_RELEASE="https://github.com/tomeksdev/NexusHub/releases"

log()  { printf '\033[1;34m[nexushub]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[nexushub]\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"

# --- Platform detection ---------------------------------------------------
. /etc/os-release 2>/dev/null || die "no /etc/os-release — unsupported distro"
case "${ID:-}:${VERSION_CODENAME:-}" in
  debian:*|ubuntu:*) : ;;
  *) die "only Debian + Ubuntu are supported; got ${ID:-unknown}" ;;
esac

ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  amd64|arm64) : ;;
  *) die "unsupported arch $ARCH — only amd64 and arm64 have release artefacts" ;;
esac

# --- Dependencies ---------------------------------------------------------
log "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl tar postgresql wireguard-tools iproute2 >/dev/null
need curl
need systemctl

# --- User + directories ---------------------------------------------------
if ! id -u "$NEXUSHUB_USER" >/dev/null 2>&1; then
  log "creating system user $NEXUSHUB_USER"
  useradd --system --home-dir "$NEXUSHUB_STATE_DIR" --shell /sbin/nologin "$NEXUSHUB_USER"
fi

install -d -m 0700 -o "$NEXUSHUB_USER" -g "$NEXUSHUB_USER" "$NEXUSHUB_STATE_DIR"
install -d -m 0750 -o "$NEXUSHUB_USER" -g "$NEXUSHUB_USER" "$NEXUSHUB_LOG_DIR"
install -d -m 0750 -o root           -g "$NEXUSHUB_USER" "$NEXUSHUB_CONFIG_DIR"

# --- Postgres -------------------------------------------------------------
# One-shot bootstrap: create the DB + role if missing, then stop. Schema
# migrations happen via the nexushub-api migrate subcommand on first start
# (or operator runs them explicitly). We never DROP — re-runs are safe.
log "preparing postgres database"
systemctl enable --now postgresql >/dev/null
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$NEXUSHUB_USER'" \
  | grep -q 1 || sudo -u postgres createuser "$NEXUSHUB_USER"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$NEXUSHUB_DB'" \
  | grep -q 1 || sudo -u postgres createdb -O "$NEXUSHUB_USER" "$NEXUSHUB_DB"

# --- Binary download ------------------------------------------------------
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if [[ "$NEXUSHUB_VERSION" == "latest" ]]; then
  log "resolving latest release"
  NEXUSHUB_VERSION=$(curl -fsSL \
    "https://api.github.com/repos/tomeksdev/NexusHub/releases/latest" \
    | grep -Po '"tag_name":\s*"\K[^"]+')
  [[ -n "$NEXUSHUB_VERSION" ]] || die "could not resolve latest release"
fi

ASSET="nexushub-api_${NEXUSHUB_VERSION#v}_linux_${ARCH}.tar.gz"
URL="$REPO_RELEASE/download/${NEXUSHUB_VERSION}/${ASSET}"

log "downloading $ASSET"
# -f: fail on HTTP errors so a 404 doesn't silently install an error page.
curl -fsSL -o "$TMPDIR/$ASSET" "$URL" || die "download failed: $URL"
tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"

install -m 0755 -o root -g root "$TMPDIR/nexushub-api" "$NEXUSHUB_BIN"

# --- Systemd unit ---------------------------------------------------------
log "installing systemd unit"
curl -fsSL -o /etc/systemd/system/nexushub-api.service \
  "$REPO_RAW/${NEXUSHUB_VERSION}/deploy/systemd/nexushub-api.service"

# Only drop the env template on a fresh install — operators who
# already configured the file should never have their secrets
# overwritten by a reinstall.
if [[ ! -f "$NEXUSHUB_CONFIG_DIR/env" ]]; then
  log "writing $NEXUSHUB_CONFIG_DIR/env (template — edit before first start)"
  curl -fsSL -o "$NEXUSHUB_CONFIG_DIR/env" \
    "$REPO_RAW/${NEXUSHUB_VERSION}/deploy/systemd/env.example"
  chmod 0600 "$NEXUSHUB_CONFIG_DIR/env"
  chown root:"$NEXUSHUB_USER" "$NEXUSHUB_CONFIG_DIR/env"
fi

systemctl daemon-reload
systemctl enable nexushub-api >/dev/null

cat <<EOF

${0##*/} finished.

Next steps:
  1. Edit ${NEXUSHUB_CONFIG_DIR}/env — at minimum set DATABASE_URL,
     JWT_SECRET, and PEER_KEY_ENCRYPTION_KEY.
  2. Run database migrations:
       sudo -u ${NEXUSHUB_USER} ${NEXUSHUB_BIN} migrate up
  3. Seed the first admin user:
       sudo -u ${NEXUSHUB_USER} ${NEXUSHUB_BIN} seed
  4. Start the API:
       sudo systemctl start nexushub-api
  5. Tail logs:
       journalctl -u nexushub-api -f

EOF
