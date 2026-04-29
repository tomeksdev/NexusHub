# NexusHub user guide

For administrators running NexusHub day-to-day. Operator install
guides live separately under
[`docs/deployment/`](../deployment/README.md); this guide assumes
you already have a running instance and an admin password.

## Contents

1. [First login](#1-first-login)
2. [Creating your first WireGuard interface](#2-creating-your-first-wireguard-interface)
3. [Adding a peer](#3-adding-a-peer)
4. [eBPF security rules](#4-ebpf-security-rules)
5. [Two-factor authentication](#5-two-factor-authentication)
6. [Audit log + observability](#6-audit-log--observability)
7. [Backup and restore](#7-backup-and-restore)

---

## 1. First login

Open the dashboard URL — `https://<your-host>` for a Caddy/Helm
deploy, or `http://localhost:8080` if you port-forwarded — and sign
in with the seeded super-admin credentials.

If you didn't seed yet, the bare-metal install command is:

```sh
sudo -u nexushub /usr/local/bin/nexushub-seed
```

with `NEXUSHUB_ADMIN_EMAIL`, `NEXUSHUB_ADMIN_USERNAME`, and
`NEXUSHUB_ADMIN_PASSWORD` exported in the env. For Docker/Helm see
the deployment guide.

After the first login, change the password from **Security →
Change password**. Seeded passwords often end up in shell history
or terraform state; rotate them.

## 2. Creating your first WireGuard interface

NexusHub doesn't ship a default interface — it manages whatever
you create explicitly so you stay in control of CIDRs and listen
ports.

1. Go to **Interfaces → New**.
2. Give it a name (`wg0` is the convention but anything matching
   `[a-z][a-z0-9_-]{0,14}` works).
3. Pick an address (e.g. `10.10.0.1/24`) and a UDP listen port
   (the default `51820` is fine unless you're already using it).
4. Save.

The API encrypts the interface private key at rest with
`PEER_KEY_ENCRYPTION_KEY` and configures the kernel device through
wgctrl. If the kernel sync fails (no `CAP_NET_ADMIN`, no
WireGuard module), the row still lands in the database — the
reconciler converges on the next restart.

## 3. Adding a peer

1. Open the interface you just created and click **Add peer**.
2. Name the peer (the device label, e.g. `alice-laptop`). The IP
   auto-allocates from the interface CIDR; override only when you
   need a specific address.
3. Optional: comma-separated `Allowed IPs`, custom `Endpoint` /
   keepalive — defaults work for most clients.
4. Save.

The peer modal opens with the rendered config. Two ways to hand
it off:

- **QR code** — scan with the WireGuard mobile app.
- **`Download .conf`** — the raw `wg-quick(8)` config; copy to
  the client and `wg-quick up <name>`.

The private key is server-generated; the client never types it
manually. To rotate the pre-shared key later, click **Rotate PSK**
in the same modal.

### CLI alternative

```sh
nexushub peer create --name alice-laptop --interface wg0
nexushub peer create --name bob-phone --interface wg0
nexushub peer list
```

`nexushub peer list` prints a table of peers with status; add
`--json` to pipe into `jq`.

## 4. eBPF security rules

Rules live under **Rules** in the sidebar. Each rule has:

- An **action**: `allow`, `deny`, `rate_limit`, or `log`.
- A **direction**: `ingress` (default), `egress`, or `both`.
- A **protocol**: `tcp`, `udp`, `icmp`, or `any`.
- Optional source and destination CIDRs.
- For `tcp` / `udp`, optional source and destination port ranges.
- For `rate_limit`, packets-per-second + optional burst.
- A **priority** (0–1000, higher wins) and an **active** toggle.

The kernel evaluates rules in descending priority. The first
match decides — a `deny` at priority 200 short-circuits an
`allow` at priority 100.

### Common patterns

**Block a noisy source on the WAN side:**
```sh
nexushub rule create --name "block-scanner" --action deny \
  --src 198.51.100.0/24 --priority 800
```

**Rate-limit ICMP per source:**
```sh
nexushub rule create --name "icmp-throttle" --action rate_limit \
  --protocol icmp --rate-pps 10 --rate-burst 50 --priority 500
```

**Just log SSH attempts:**
```sh
nexushub rule create --name "log-ssh" --action log \
  --protocol tcp --dst-port-from 22 --dst-port-to 22
```

Logged events stream into the `connection_logs` table; query them
via the audit log viewer or directly with psql.

### When kernel enforcement is a no-op

The rules editor and CLI work even when the kernel datapath
isn't loaded (`NEXUSHUB_XDP_IFACE` / `NEXUSHUB_TC_IFACE` unset,
or no `CAP_BPF`). Rules persist to the DB and the kernel-side
reconciler converges on next start with the right caps. The
RulesPage banner notes this so it's not surprising.

## 5. Two-factor authentication

Highly recommended for every admin account.

1. **Security → Enable 2FA**.
2. Scan the QR code with Google Authenticator, 1Password, Bitwarden,
   or any RFC 6238 TOTP app. The base32 secret is shown for manual
   entry too.
3. Type the 6-digit code from the app to confirm.

After enabling, login takes two steps: password first, then code.
The CLI handles this automatically (`nexushub login` prompts for
the code when needed).

To disable 2FA you need both your password and a current code —
this defeats a stolen-session attacker from removing the second
factor on a victim's account.

## 6. Audit log + observability

**Audit log** (sidebar → Audit log) is the append-only record of
every authenticated action: logins, logouts, password changes,
2FA enroll/disable, peer creates/deletes, rule changes. Filter by
action, result, or time range. Retention defaults to 90 days
(`AUDIT_RETENTION_DAYS`); rows older than the cutoff are pruned
hourly by the API process itself.

**Metrics** are exposed at `/api/v1/metrics` for Prometheus
scrape. Drop the bundled dashboard from
[`docs/deployment/grafana/`](../deployment/grafana/) into Grafana
to see HTTP latency, DB pool, eBPF map cardinality, and per-peer
WireGuard throughput. The alert rules under
[`docs/deployment/prometheus/`](../deployment/prometheus/) cover
the page-worthy failure modes.

**Tracing** activates when `OTEL_EXPORTER_OTLP_ENDPOINT` is set —
HTTP requests + every pgx query land as spans. Disabled = noop;
no overhead.

## 7. Backup and restore

The complete operator runbook is in
[`docs/deployment/backup-restore.md`](../deployment/backup-restore.md).
Short version:

```sh
./scripts/backup.sh           # creates a dated .sql.gz
./scripts/restore.sh <file>   # refuses if DB has tables; --force overrides
```

**Two things to back up separately:**

1. The Postgres dump.
2. `PEER_KEY_ENCRYPTION_KEY` — the master key encrypting peer
   private keys + TOTP secrets. Without it, a DB restore can't
   decrypt anything sensitive. Store it in your secrets manager,
   not next to the database backup.

A quarterly DR drill (restore into a throwaway, run
`nexushub doctor`, verify a peer config renders) is the only way
to know your backups actually work.
