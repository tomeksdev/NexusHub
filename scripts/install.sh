#!/usr/bin/env bash
# NexusHub bare-metal installer for Debian + Ubuntu.
#
# Installs the API server (nexushub-api), the migration runner
# (nexushub-migrate), the first-admin seeder (nexushub-seed),
# their systemd unit, postgresql + wireguard-tools, then runs the
# migrations, seeds the first admin, and starts the service.
#
# One-liner bootstrap (replace the tag with the release you want):
#   curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
#     | sudo NEXUSHUB_VERSION=v2.0.0-preview.3 bash
#
# Interactive mode (operator at a real terminal) prompts via
# /dev/tty so the curl-pipe pattern above still works. Non-
# interactive runs (no /dev/tty) read every value from env vars
# and exit non-zero with a clear missing-var error.
#
# Idempotent: re-running upgrades binaries + refreshes the unit
# without touching /etc/nexushub/env or the database. Pass
# NEXUSHUB_REGENERATE_ENV=1 to force a fresh env write.

set -euo pipefail

# --- Constants -------------------------------------------------------------
NEXUSHUB_VERSION="${NEXUSHUB_VERSION:-latest}"
NEXUSHUB_USER="${NEXUSHUB_USER:-nexushub}"
NEXUSHUB_DB="${NEXUSHUB_DB:-nexushub}"
NEXUSHUB_STATE_DIR="${NEXUSHUB_STATE_DIR:-/var/lib/nexushub}"
NEXUSHUB_LOG_DIR="${NEXUSHUB_LOG_DIR:-/var/log/nexushub}"
NEXUSHUB_CONFIG_DIR="${NEXUSHUB_CONFIG_DIR:-/etc/nexushub}"
NEXUSHUB_BIN_DIR="${NEXUSHUB_BIN_DIR:-/usr/local/bin}"
# Stable runtime directory the API process can read. Holds the SQL
# migrations, the env.example template, and any future assets the
# binaries need at startup. Owned root:nexushub, mode 0750.
NEXUSHUB_RUNTIME_DIR="${NEXUSHUB_RUNTIME_DIR:-/opt/nexushub}"
NEXUSHUB_BPF_PIN_DIR="${NEXUSHUB_BPF_PIN_DIR:-/sys/fs/bpf/nexushub}"
REPO_RELEASE="https://github.com/tomeksdev/NexusHub/releases"

# --- Logging ---------------------------------------------------------------
log()  { printf '\033[1;34m[nexushub]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[nexushub]\033[0m %s\n' "$*" >&2; }
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

# --- TTY detection ---------------------------------------------------------
# The documented one-liner is `curl ... | sudo bash`, which means
# stdin is the script stream — `-t 0` reports non-interactive even
# when there's an operator at a real terminal. Detect via /dev/tty
# instead so the curl-pipe install can prompt; non-interactive runs
# (cloud-init, container build) usually have neither stdin nor
# /dev/tty and fall through to the env-var path.
if [[ -r /dev/tty && -w /dev/tty ]]; then
  INTERACTIVE=1
else
  INTERACTIVE=0
fi

# prompt VAR_NAME "Question text" [default]
# Reads from $VAR_NAME if already set in the env. Otherwise:
#   interactive  → prompt via /dev/tty; accept default on empty
#                  input.
#   non-interactive → fail with a clear error if no env var and no
#                     default.
prompt() {
  local var="$1" question="$2" default="${3:-}"
  if [[ -n "${!var:-}" ]]; then
    return 0
  fi
  if (( INTERACTIVE == 0 )); then
    [[ -n "$default" ]] || die "missing env var: $var (no TTY, no default)"
    printf -v "$var" '%s' "$default"
    return 0
  fi
  local prompt_text="$question"
  [[ -n "$default" ]] && prompt_text="$question [$default]"
  printf '%s: ' "$prompt_text" >/dev/tty
  local answer
  read -r answer </dev/tty
  [[ -z "$answer" && -n "$default" ]] && answer="$default"
  [[ -n "$answer" ]] || die "$var is required"
  printf -v "$var" '%s' "$answer"
}

# prompt_secret VAR_NAME "Question text" [confirm?]
# Same as prompt but with hidden input and optional double-confirm.
prompt_secret() {
  local var="$1" question="$2" confirm="${3:-no}"
  if [[ -n "${!var:-}" ]]; then
    return 0
  fi
  (( INTERACTIVE == 1 )) || die "missing env var: $var (no TTY)"
  local answer1 answer2
  while :; do
    printf '%s: ' "$question" >/dev/tty
    read -rs answer1 </dev/tty
    printf '\n' >/dev/tty
    [[ -n "$answer1" ]] || { warn "value cannot be empty"; continue; }
    if [[ "$confirm" == "confirm" ]]; then
      printf 'Confirm %s: ' "$question" >/dev/tty
      read -rs answer2 </dev/tty
      printf '\n' >/dev/tty
      if [[ "$answer1" != "$answer2" ]]; then
        warn "values did not match — try again"
        continue
      fi
    fi
    break
  done
  printf -v "$var" '%s' "$answer1"
}

# --- Dependencies ---------------------------------------------------------
log "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl tar openssl postgresql wireguard-tools iproute2 >/dev/null
need curl
need openssl
need systemctl

# --- Resolve version ------------------------------------------------------
if [[ "$NEXUSHUB_VERSION" == "latest" ]]; then
  log "resolving latest release"
  NEXUSHUB_VERSION=$(curl -fsSL \
    "https://api.github.com/repos/tomeksdev/NexusHub/releases/latest" \
    | grep -Po '"tag_name":\s*"\K[^"]+' || true)
  [[ -n "$NEXUSHUB_VERSION" ]] || die "could not resolve latest release"
fi

# --- Collect operator input -----------------------------------------------
# Defaults are sensible for a single-host install; the operator can
# override per env-var or interactively. Env-var names mirror the
# settings the API itself reads where possible.
log "configuring install (interactive=${INTERACTIVE})"

prompt        NEXUSHUB_WG_ENDPOINT_HOST  "WireGuard public endpoint host or IP"
prompt        NEXUSHUB_WG_ENDPOINT_PORT  "WireGuard endpoint port"             "51820"
prompt        NEXUSHUB_PORT              "Web GUI / API port"                  "8080"
prompt_secret NEXUSHUB_DB_PASSWORD       "PostgreSQL password for the nexushub role" confirm
prompt        NEXUSHUB_ADMIN_EMAIL       "Initial admin email"
prompt        NEXUSHUB_ADMIN_USERNAME    "Initial admin username"              "admin"
prompt_secret NEXUSHUB_ADMIN_PASSWORD    "Initial admin password"              confirm

# Auto-generated secrets. openssl rand is portable and the right
# entropy budget for both fields.
JWT_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
PEER_KEY_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr -d '\n')"

# --- User + directories ---------------------------------------------------
if ! id -u "$NEXUSHUB_USER" >/dev/null 2>&1; then
  log "creating system user $NEXUSHUB_USER"
  useradd --system --home-dir "$NEXUSHUB_STATE_DIR" --shell /sbin/nologin "$NEXUSHUB_USER"
fi

install -d -m 0700 -o "$NEXUSHUB_USER" -g "$NEXUSHUB_USER" "$NEXUSHUB_STATE_DIR"
install -d -m 0750 -o "$NEXUSHUB_USER" -g "$NEXUSHUB_USER" "$NEXUSHUB_LOG_DIR"
install -d -m 0750 -o root            -g "$NEXUSHUB_USER" "$NEXUSHUB_CONFIG_DIR"
install -d -m 0750 -o root            -g "$NEXUSHUB_USER" "$NEXUSHUB_RUNTIME_DIR"

# --- Postgres -------------------------------------------------------------
# Create the role + DB if missing, always sync the role's password
# to whatever the operator just supplied. We never DROP — operators
# upgrading from older installs keep their data.
log "preparing postgres database"
systemctl enable --now postgresql >/dev/null
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$NEXUSHUB_USER'" \
  | grep -q 1 || sudo -u postgres createuser "$NEXUSHUB_USER"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$NEXUSHUB_DB'" \
  | grep -q 1 || sudo -u postgres createdb -O "$NEXUSHUB_USER" "$NEXUSHUB_DB"

# Apply the operator-supplied password. ALTER USER is idempotent;
# the SQL is piped via stdin so the password never shows up in
# `ps`/`ps -ef` output.
sudo -u postgres psql -q <<SQL
ALTER USER "$NEXUSHUB_USER" WITH PASSWORD '$NEXUSHUB_DB_PASSWORD';
SQL

# --- Binary download ------------------------------------------------------
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

ASSET="nexushub-api_${NEXUSHUB_VERSION#v}_linux_${ARCH}.tar.gz"
URL="$REPO_RELEASE/download/${NEXUSHUB_VERSION}/${ASSET}"

log "downloading $ASSET"
# -f: fail on HTTP errors so a 404 doesn't silently install an error page.
curl -fsSL -o "$TMPDIR/$ASSET" "$URL" || die "download failed: $URL"

# Optional checksum verification. If a checksums.txt exists for this
# version, fetch it and verify; if not, log and continue (older
# releases predate the checksums upload).
CHECKSUMS_URL="$REPO_RELEASE/download/${NEXUSHUB_VERSION}/nexushub_${NEXUSHUB_VERSION#v}_checksums.txt"
if curl -fsSL -o "$TMPDIR/checksums.txt" "$CHECKSUMS_URL" 2>/dev/null; then
  log "verifying sha256"
  (cd "$TMPDIR" && grep "  $ASSET\$" checksums.txt | sha256sum -c -) \
    || die "checksum verification failed for $ASSET"
else
  warn "no checksums.txt at $CHECKSUMS_URL — skipping verification"
fi

tar -xzf "$TMPDIR/$ASSET" -C "$TMPDIR"

# Install all three binaries. Operator-managed reinstalls replace
# the previous copies; mode 0755 root:root keeps them runnable but
# tamper-evident.
for bin in nexushub-api nexushub-migrate nexushub-seed; do
  [[ -f "$TMPDIR/$bin" ]] || die "$bin missing from $ASSET"
  install -m 0755 -o root -g root "$TMPDIR/$bin" "$NEXUSHUB_BIN_DIR/$bin"
done

# --- Runtime files --------------------------------------------------------
# Migrations + supporting docs go into the runtime dir. The migrate
# binary reads `file://migrations` relative to its CWD, so we need a
# stable location the nexushub user can read; the operator's
# current shell pwd doesn't qualify (and broke preview.2).
log "installing runtime files into $NEXUSHUB_RUNTIME_DIR"
if [[ -d "$TMPDIR/migrations" ]]; then
  rm -rf "$NEXUSHUB_RUNTIME_DIR/migrations"
  cp -a "$TMPDIR/migrations" "$NEXUSHUB_RUNTIME_DIR/migrations"
else
  die "migrations/ missing from $ASSET — release archive is incomplete"
fi
for f in env.example LICENSE README.md; do
  [[ -f "$TMPDIR/$f" ]] && cp -a "$TMPDIR/$f" "$NEXUSHUB_RUNTIME_DIR/$f"
done
chown -R root:"$NEXUSHUB_USER" "$NEXUSHUB_RUNTIME_DIR"
# g+rX so directories are traversable + files readable; owner keeps
# write to roll forward / replace artefacts on reinstall.
chmod -R u=rwX,g=rX,o= "$NEXUSHUB_RUNTIME_DIR"

# --- Systemd unit ---------------------------------------------------------
log "installing systemd unit"
install -m 0644 -o root -g root "$TMPDIR/nexushub-api.service" \
  /etc/systemd/system/nexushub-api.service

# --- BPF pin directory ----------------------------------------------------
# eBPF maps survive an API restart only when pinned under bpffs.
# The service runs as `nexushub`; it can't mount filesystems or
# create directories under /sys/fs/bpf/ at runtime. We do both
# here, before systemctl start, so the loader finds the dir
# already prepared with the right ownership.
log "preparing bpf pin dir $NEXUSHUB_BPF_PIN_DIR"
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
install -d -m 0700 -o "$NEXUSHUB_USER" -g "$NEXUSHUB_USER" "$NEXUSHUB_BPF_PIN_DIR"

# --- Env file -------------------------------------------------------------
ENV_FILE="$NEXUSHUB_CONFIG_DIR/env"
write_env() {
  log "writing $ENV_FILE"
  install -m 0600 -o root -g "$NEXUSHUB_USER" /dev/null "$ENV_FILE"
  cat >"$ENV_FILE" <<EOF
# /etc/nexushub/env — generated by install.sh on $(date -Iseconds).
# Edit with care; never share this file. Restart the service after
# any change: systemctl restart nexushub-api.

DATABASE_URL=postgres://${NEXUSHUB_USER}:${NEXUSHUB_DB_PASSWORD}@localhost:5432/${NEXUSHUB_DB}?sslmode=disable

# Generated automatically; do not regenerate without rotating every
# peer's stored private key.
JWT_SECRET=${JWT_SECRET}
PEER_KEY_ENCRYPTION_KEY=${PEER_KEY_ENCRYPTION_KEY}

# WireGuard endpoint the generated peer configs advertise.
WG_ENDPOINT=${NEXUSHUB_WG_ENDPOINT_HOST}:${NEXUSHUB_WG_ENDPOINT_PORT}

# Web GUI / API listener.
PORT=${NEXUSHUB_PORT}
GIN_MODE=release

JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
AUDIT_RETENTION_DAYS=90
EOF
}

if [[ ! -f "$ENV_FILE" ]] || [[ "${NEXUSHUB_REGENERATE_ENV:-0}" == "1" ]]; then
  write_env
else
  log "keeping existing $ENV_FILE — pass NEXUSHUB_REGENERATE_ENV=1 to overwrite"
fi

# --- Migrations + seed ----------------------------------------------------
# Run from the runtime dir so `file://migrations` resolves. `env -i`
# clears the parent environment; we then pass exactly what the
# binaries need from /etc/nexushub/env. The runtime dir is the CWD
# via `cd` inside the sudo command (sudo doesn't have --chdir on
# every Debian/Ubuntu version we support).
run_as_nexushub() {
  sudo -u "$NEXUSHUB_USER" \
    env -i \
    PATH="/usr/local/bin:/usr/bin:/bin" \
    HOME="$NEXUSHUB_STATE_DIR" \
    $(grep -v '^[[:space:]]*#' "$ENV_FILE" | grep -v '^[[:space:]]*$' | xargs) \
    sh -c "cd '$NEXUSHUB_RUNTIME_DIR' && exec \"\$@\"" -- "$@"
}

log "running migrations"
run_as_nexushub "$NEXUSHUB_BIN_DIR/nexushub-migrate" up

# Admin password lands in the seed binary's env at runtime only —
# never written to ENV_FILE. seed is idempotent: a second run with
# the same admin email returns success without creating duplicates.
log "seeding first admin user"
run_as_nexushub \
  env NEXUSHUB_ADMIN_EMAIL="$NEXUSHUB_ADMIN_EMAIL" \
      NEXUSHUB_ADMIN_USERNAME="$NEXUSHUB_ADMIN_USERNAME" \
      NEXUSHUB_ADMIN_PASSWORD="$NEXUSHUB_ADMIN_PASSWORD" \
      "$NEXUSHUB_BIN_DIR/nexushub-seed"

# --- Start the service ----------------------------------------------------
log "enabling + starting nexushub-api"
systemctl daemon-reload
systemctl enable nexushub-api >/dev/null
systemctl restart nexushub-api

# --- Health check ---------------------------------------------------------
# Give the API up to 30s to become healthy. The systemd unit's
# Restart=on-failure means a transient failure here would loop; we
# bail loudly if /health doesn't come up so the operator notices.
log "waiting for /api/v1/health"
HEALTH_URL="http://127.0.0.1:${NEXUSHUB_PORT}/api/v1/health"
for _ in $(seq 1 30); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "$HEALTH_URL" >/dev/null \
  || die "health check failed after 30s — inspect journalctl -u nexushub-api"

# UI root check. Not fatal — operators running an API-only build
# (no embedded frontend) still want to finish the install. A 404
# here is a clear "frontend missing" signal but not a stop.
UI_URL="http://127.0.0.1:${NEXUSHUB_PORT}/"
if curl -fsSI "$UI_URL" 2>/dev/null | head -1 | grep -q '200'; then
  UI_OK=1
else
  UI_OK=0
  warn "UI root at $UI_URL did not return 200 — running API-only?"
fi

# --- Success summary ------------------------------------------------------
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$SERVER_IP" ]] || SERVER_IP="$(hostname)"

printf '\n\033[1;32m✓ NexusHub installed successfully.\033[0m\n\n'

if (( UI_OK == 1 )); then
  cat <<EOF
Web / API:
  http://${SERVER_IP}:${NEXUSHUB_PORT}
  (login as ${NEXUSHUB_ADMIN_USERNAME} / ${NEXUSHUB_ADMIN_EMAIL})

EOF
else
  cat <<EOF
API (UI not bundled in this build):
  http://${SERVER_IP}:${NEXUSHUB_PORT}/api/v1/health

EOF
fi

cat <<EOF
Service:
  systemctl status nexushub-api

Logs:
  journalctl -u nexushub-api -f

Config:
  ${ENV_FILE}  (mode 0600, root:${NEXUSHUB_USER})

Runtime:
  ${NEXUSHUB_RUNTIME_DIR}/migrations  (read by nexushub-migrate)
  ${NEXUSHUB_BPF_PIN_DIR}                (eBPF map pin directory)

Next:
  Open the dashboard, rotate the admin password from the profile
  page, create your first WireGuard interface, and add a peer.
EOF
