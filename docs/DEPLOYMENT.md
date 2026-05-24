# NexusHub — production deployment guide

This is the top-level operations doc for a `v2.0.0-preview.1`
install. It covers what the host needs, the three supported
deployment shapes, the complete env-var reference, and the
hardening guardrails that turn a working install into a
defensible one.

Per-shape runbooks live alongside this doc:

- [`deployment/README.md`](deployment/README.md) — compose /
  bare-metal / Helm three-way index
- [`deployment/backup-restore.md`](deployment/backup-restore.md)
- [`deployment/observability.md`](deployment/observability.md)
- [`deployment/load-testing.md`](deployment/load-testing.md)
- [`deployment/migration-recovery.md`](deployment/migration-recovery.md)

For development (running the stack on your laptop), see
[`DEVELOPMENT.md`](DEVELOPMENT.md).

---

## 📋 Infrastructure prerequisites

### Linux kernel

NexusHub's data plane runs in the kernel. The kernel version on
the host that runs the API process is therefore part of the
deployment surface.

| Feature | Required for | Kernel min |
|---|---|---|
| `bpf_loop` helper | v2.1 rule engine — every packet iterates the active rule table | **5.17** |
| `BPF_MAP_TYPE_RINGBUF` | `log_events` ringbuf for `ACTION_LOG` rule output | **5.8** |
| `BPF_MAP_TYPE_PERCPU_HASH` | rate-limit token buckets, hit counters | 4.6 |
| `tcx` link API | TC ingress attach on `wgN` (used by the loader) | **6.6** preferred (`tc_act_skb_change_head_extra`); 5.18+ for tcx itself |
| WireGuard kernel module | Tunnel itself | 5.6 (mainlined) |

**Tested on:** Linux 6.8 (Ubuntu 24.04, Debian 12 backports).
Older kernels won't load the v2.1 BPF program — the loader's
capability probe at startup logs `bpf_loop=missing` and the
control plane refuses to start with that error.

The capability probe is intentional: a silent fallback to "no
enforcement" would be a worse outcome than failing fast.

### Network

- One **public WAN NIC** (or NAT-exposed equivalent) — XDP attaches
  here for pre-tunnel filtering.
- One UDP port per WireGuard interface (default `51820/udp`),
  reachable from the public internet. Multiple interfaces use
  consecutive or operator-chosen ports.
- One TCP port for the API + dashboard (default `8080/tcp`),
  exposed behind a reverse proxy in production. Direct exposure
  is supported but discouraged (no TLS termination in the API
  itself).
- IPv4 forwarding (`net.ipv4.ip_forward=1`) and, if applicable,
  IPv6 forwarding (`net.ipv6.conf.all.forwarding=1`). The installer
  + docker-compose stack write these via sysctl drop-ins.

### Host system

| Requirement | Why |
|---|---|
| systemd 247+ (`AmbientCapabilities`, `ReadWritePaths`) | The shipped unit relies on systemd's modern hardening primitives |
| WireGuard kernel module loaded (`modprobe wireguard`) | Pre-`5.6` hosts need the DKMS package; built-in on every supported kernel |
| `/dev/net/tun` accessible | Required for wg device creation; `PrivateDevices=no` is set explicitly in the unit |
| `bpffs` mounted at `/sys/fs/bpf` | Standard on all modern distros; the loader pins maps under `/sys/fs/bpf/nexushub` |
| PostgreSQL 16+ reachable | Same host, separate container, or remote managed DB — all work |

### Required kernel capabilities

The API process needs **three** capabilities:

- `CAP_NET_ADMIN` — `wgctrl-go` device CRUD, address management
- `CAP_BPF` — load programs, manage maps, attach TC/XDP
- `CAP_NET_RAW` — open the tun device on older kernels that
  predate `CAP_NET_ADMIN`-only mode

Anything else is dropped. The systemd unit at
`deploy/systemd/nexushub-api.service` sets the bounding set
explicitly. The Helm chart's `dataPlane.enabled` toggle wires the
same three capabilities into the pod when the operator wants the
kernel sync to run inside Kubernetes (recommended pattern: API in
k8s, kernel sync via systemd on the actual WG hosts — see Helm
chart README).

---

## 📦 Production build manifest

### Three deployment shapes, briefly

| Shape | When to use | Where it lives |
|---|---|---|
| **Docker compose** | Single host, evaluation, small fleets | `docker/docker-compose.prod.yml` + Caddy TLS |
| **Bare metal + systemd** | Operators who want the kernel module + API on the same dedicated VM | `scripts/install.sh` + `deploy/systemd/` |
| **Kubernetes / Helm** | Multi-replica API; kernel sync usually stays bare-metal | `deploy/helm/nexushub/` |

The per-shape walkthroughs are in
[`deployment/README.md`](deployment/README.md). Below is the
production-bake quick reference.

### Docker compose (production)

```bash
git clone https://github.com/tomeksdev/NexusHub.git
cd NexusHub
cp docker/.env.example docker/.env
# Edit docker/.env: set every CHANGE_ME secret + the public hostname.
docker compose -f docker/docker-compose.prod.yml --env-file docker/.env up -d
```

The prod compose stack runs:

1. `postgres` (16-alpine, named volume for data)
2. `api` (nexushub binary, dropped to `CAP_NET_ADMIN`+`CAP_BPF`
   only, read-only frontend dist volume)
3. `frontend-init` (one-shot — copies the SPA bundle into the
   shared volume on tag change)
4. `caddy` (2-alpine, serves `/api/*` → `api:8080`, SPA from
   `/srv/nexushub`, ACME via Let's Encrypt on ports 80+443)

The `caddy` service handles TLS automatically using the
`PUBLIC_HOSTNAME` env var. Behind a load balancer, set
`tls internal` in `docker/Caddyfile` instead.

### Bare-metal one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
  | sudo NEXUSHUB_VERSION=v2.0.0-preview.1 bash
```

The installer is idempotent:

- Creates `nexushub` system user, `/var/lib/nexushub`,
  `/var/log/nexushub`
- Creates the `nexushub` Postgres role + DB if missing (skipped
  on hosts where the operator provisions DB out of band — set
  `DATABASE_URL` first and the role check passes through)
- Downloads the tarball for the requested tag (or `latest` via
  GitHub API), unpacks `nexushub-api` + `nexushub-migrate` +
  `nexushub-seed` to `/usr/local/bin/`
- Installs the systemd unit + env template at
  `/etc/nexushub/env` (chmod 0600); **preserves existing env**
  across re-runs
- Runs `systemctl daemon-reload && systemctl enable
  nexushub-api`
- Prints the next-step checklist

Operator finishes by editing `/etc/nexushub/env`, running
`/usr/local/bin/nexushub-migrate up`, then
`systemctl start nexushub-api`.

### Helm

```bash
helm install nexushub ./deploy/helm/nexushub \
  --set image.tag=v2.0.0-preview.1 \
  --set secrets.jwtSecret=$(openssl rand -hex 32) \
  --set secrets.peerKeyEncryptionKey=$(openssl rand -base64 32) \
  --set postgres.existingSecret=nexushub-postgres
```

Production deployments should always use
`secrets.existingSecret` + `postgres.existingSecret` so chart
upgrades don't replay the in-values secrets. The migrate Job
runs as a `pre-install` / `pre-upgrade` hook so the schema is
caught up before the API pod rolls.

See [`deploy/helm/nexushub/README.md`](../deploy/helm/nexushub/README.md)
for the `values.yaml` reference.

### Environment variable reference

The `nexushub-api` process reads its config from environment
variables. The systemd unit sources them from
`/etc/nexushub/env`; Docker compose from `docker/.env`; Helm
from the chart's Secret + ConfigMap.

| Var | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string. `sslmode=require` in production. |
| `JWT_SECRET` | yes | — | HS256 signing key for access tokens. `openssl rand -hex 32`. |
| `PEER_KEY_ENCRYPTION_KEY` | yes | — | 32-byte AES-256-GCM key encrypting `wg_peers.private_key` and `users.totp_secret`. Base64-encoded. `openssl rand -base64 32`. |
| `PORT` | no | `8080` | API listen port. |
| `GIN_MODE` | no | `release` | Set to `debug` for verbose request logging. |
| `JWT_ACCESS_EXPIRY` | no | `15m` | Access token lifetime. |
| `JWT_REFRESH_EXPIRY` | no | `168h` | Refresh token lifetime (7 days). |
| `WG_ENDPOINT` | recommended | — | `host:port` advertised in generated peer configs. Falls back to the interface row's `endpoint` column. |
| `WG_INTERFACE` | no | `wg0` | Default interface name for the first-admin seeder. |
| `WG_LISTEN_PORT` | no | `51820` | Default listen port for the seeded interface. |
| `AUDIT_RETENTION_DAYS` | no | `90` | Audit log retention. `0` disables the prune loop. |
| `AUDIT_RETENTION_SCAN` | no | `1h` | How often the prune loop ticks. |
| `NEXUSHUB_ADMIN_EMAIL` | seed only | `admin@example.com` | Seed user email. |
| `NEXUSHUB_ADMIN_USERNAME` | seed only | `admin` | Seed user username. |
| `NEXUSHUB_ADMIN_PASSWORD` | seed only | `change-me` | Seed user initial password. Rotate via the UI on first login. |
| `NEXUSHUB_SEED_WG` | seed only | `0` | When `1`, the seeder also creates a default `wg0` interface. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | no | — | SMTP for password-reset email (preview leaves email features minimal). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | — | OTLP/gRPC endpoint for traces. Empty disables tracing (noop provider). |
| `OTEL_EXPORTER_OTLP_INSECURE` | no | `false` | Set `true` for plain-text OTLP (local collectors). |
| `OTEL_SERVICE_NAME` | no | `nexushub` | Resource attribute for traces. |
| `OTEL_TRACES_SAMPLER_ARG` | no | `0.1` | Tail sampling rate (0.0–1.0). |

Secrets-management note: never set `JWT_SECRET` or
`PEER_KEY_ENCRYPTION_KEY` via a process argument or a non-restricted
config map. The systemd `EnvironmentFile=` directive expects
chmod 0600 (root-readable only). Helm's `existingSecret` pattern
is the recommended path on Kubernetes.

---

## 🛡️ System hardening + security guardrails

### Capabilities (Linux)

The systemd unit drops every capability except the three the data
plane needs (`CAP_NET_ADMIN`, `CAP_BPF`, `CAP_NET_RAW`). Don't
loosen this:

- No `CAP_SYS_ADMIN` — the API doesn't need filesystem-level
  privileges; reach for `CAP_BPF` (kernel 5.8+) instead
- No `CAP_DAC_OVERRIDE` — file permissions stay enforced
- `NoNewPrivileges=yes` — children can't escalate

The Docker compose stack does the equivalent via
`cap_drop: [ALL]` + `cap_add: [NET_ADMIN, BPF, NET_RAW]` in
`docker-compose.prod.yml`. The Helm chart mirrors it in
`securityContext.capabilities`. Audit any change to these lists
against the production checklist before deploying.

### Filesystem isolation

The systemd unit ships with:

```ini
ProtectSystem=strict     # /usr, /boot, /etc read-only
ProtectHome=yes          # /home, /root not accessible
PrivateTmp=yes           # private /tmp + /var/tmp
ReadWritePaths=/var/lib/nexushub /var/log/nexushub
ReadOnlyPaths=/etc/nexushub
```

`PrivateDevices` is **off** because the API needs `/dev/net/tun`
(WireGuard) and `bpf()` syscalls. Everything else stays
restricted.

### Frontend hardening

The SPA bundle is **CDN-free** — every asset is same-origin. The
reverse proxy should add CSP headers that match:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  font-src 'self' data:;
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
```

`'unsafe-inline'` on `style-src` is needed for Tailwind's inline
style attribute on dynamically-coloured components; remove it
once the SPA stops using inline styles. Other directives can
stay tight.

### Reverse proxy (Caddy / nginx / Traefik)

NexusHub does **not** terminate TLS in the API process. Run it
behind a proxy that handles:

- **TLS termination** (Let's Encrypt via Caddy is the path the
  compose stack uses)
- **HTTP → HTTPS redirect** (`autohttps`)
- **HSTS** (`Strict-Transport-Security: max-age=63072000;
  includeSubDomains; preload`)
- **Trusted-proxy stripping** of `X-Forwarded-*` headers from
  untrusted sources. The API trusts the first hop only.

Caddy snippet (from `docker/Caddyfile`):

```caddy
example.com {
    encode zstd gzip
    handle_path /api/* {
        reverse_proxy api:8080
    }
    handle {
        root * /srv/nexushub
        try_files {path} /index.html
        file_server
        header /assets/* Cache-Control "public, max-age=31536000, immutable"
        header /         Cache-Control "no-cache"
    }
}
```

For nginx, the equivalent template is in
[`deployment/observability.md`](deployment/observability.md).

### Firewall (host-level)

The minimum ruleset for a single-host install:

```
# Inbound
22/tcp     — SSH (rate-limit + key-only)
80/tcp     — HTTP (Let's Encrypt validation; redirects to 443)
443/tcp    — HTTPS (dashboard + API)
51820/udp  — WireGuard (default; one rule per interface)

# Drop everything else inbound. Outbound stays open unless you
# have a reason to lock it (e.g. egress proxy).
```

`ufw` example:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 51820/udp
sudo ufw enable
```

eBPF rules on the WAN side fire **before** iptables/nftables and
**before** the kernel's routing decision (XDP runs at the driver
RX path). Don't expect host firewall rules to act as a fallback
for the eBPF program — they're complementary layers, both
required.

### Database hardening

- `sslmode=require` (or `verify-full` with a trusted CA) on every
  production `DATABASE_URL`
- Dedicated `nexushub` role with `LOGIN`, `CREATE` on the
  `nexushub` schema only; no superuser
- `pgaudit` if your compliance bracket needs full statement
  logging; the app's audit log covers mutations but not reads
- Backups via `scripts/backup.sh` running on a systemd timer
  (default daily, retain 14). See
  [`deployment/backup-restore.md`](deployment/backup-restore.md).

The DB-only backup is **useless without
`PEER_KEY_ENCRYPTION_KEY`** — the peer private keys + TOTP
secrets are encrypted at rest. Back up the env file (or the
secret it lives in) separately, ideally to a different
destination.

### Operational verification

Before exposing a fresh install to a public network, walk through:

1. `curl -fsS https://<host>/api/v1/health` returns `200 ok`
2. First-admin login works, password rotation accepted
3. TOTP enrollment completes (preview keeps this optional but
   recommended for any admin)
4. A test peer connects from a real client; `wg show <iface>` shows
   the handshake within 60 s
5. With at least two interfaces, the auto-generated `system:deny`
   rules appear in the Rules table as **active** with the
   "system" badge; cross-location traffic blocks unless an
   explicit allow rule overrides
6. `/api/v1/metrics` returns Prometheus exposition format and
   includes `nexushub_ebpf_map_entries{map="rule_table_v4"}` with
   a non-zero value
7. Tearing down + reinstalling the API process leaves the kernel
   maps intact (pinned at `/sys/fs/bpf/nexushub`) and the next
   start finds them — confirms the operator can hot-reload
   without dropping rule state

If any of those fail, see
[`deployment/migration-recovery.md`](deployment/migration-recovery.md)
for triage steps.
