# Migrating from NexusHub v1.0.0

NexusHub v2.0.0 is a complete rewrite. Same problem (manage a
WireGuard server through a web dashboard) but a different
architecture: Go API + React frontend + PostgreSQL + eBPF, instead
of the v1 Python WebGUI + flat files.

This document covers what the upgrade actually requires for an
operator running a v1 install today. Most of it is a one-shot
data migration; nothing carries forward as-is.

## What's incompatible

| Subsystem | v1 | v2 |
|---|---|---|
| Backend language | Python | Go |
| Web framework | Flask | Gin |
| Frontend | Server-rendered Jinja templates | React + Vite SPA |
| State storage | `wg0.conf` flat files | PostgreSQL 16+ |
| Auth | HTTP basic | JWT + refresh-token rotation + optional TOTP |
| Install path | `wg-server-install.sh` shell script | systemd / Docker / Helm |
| eBPF security rules | None | XDP + TC clsact, runtime-tunable maps |
| API | None (web UI only) | OpenAPI 3.0, CLI, programmatic access |

Because state lived in WireGuard config files in v1, there's no
direct database upgrade path. The migration is a one-shot import.

## Plan the cutover

This is a **destructive, one-way migration**. Schedule a
maintenance window, give peers advance warning that they may need
to re-scan a QR or re-import a `.conf` after the cut, and have a
rollback plan: keep the v1 install runnable on a snapshot for at
least a week.

The data the import preserves:

- Server private + public keys (from `/etc/wireguard/wg0.conf`).
- Listen port + interface address.
- Peer name, allowed IPs, public key, pre-shared key (if set).

What it doesn't preserve:

- Operator passwords (no equivalent in v1; you create new
  accounts in v2).
- Bandwidth / connection history (v1 didn't store it).
- Per-peer custom settings that lived only in shell scripts.

## Step 1 — Stand up v2 alongside v1

Pick a deployment shape from the
[deployment guide](./deployment/README.md) and bring v2 up on a
non-conflicting port (or a different host entirely). Don't
forward the public WireGuard endpoint at v2 yet.

Verify v2 is healthy:

```sh
nexushub doctor
```

Should print three green probes (config / health / auth).

## Step 2 — Export v1 state

On the v1 host:

```sh
sudo cat /etc/wireguard/wg0.conf > /tmp/v1-wg0.conf
sudo wg show wg0 dump > /tmp/v1-runtime-state.txt   # optional, runtime view
```

Copy these to wherever you can run the v2 CLI from. The flat-file
format is straightforward to parse — server section first, then
one `[Peer]` block per client.

## Step 3 — Import into v2

The v2 CLI doesn't ship a `config import` command yet (deferred
on safety grounds — see the open Phase 8 item in TODO.md). For
now, import is a manual but mechanical translation:

1. **Create the interface** with the same private key + listen
   port:

   ```sh
   nexushub login                                    # one-time
   # In the UI: Interfaces → New
   # Or via psql if you prefer scripted imports — schema in
   # migrations/002_wireguard.up.sql.
   ```

2. **Add each peer** preserving its public key + allowed IPs:

   ```sh
   nexushub peer create --interface wg0 \
     --name alice-laptop \
     --ip 10.10.0.2 \
     --allowed-ips 10.10.0.2/32
   ```

   v2 generates a fresh server-side keypair by default. To carry
   the v1 peer's existing public key (so the client doesn't need a
   new config), use the API directly — see
   `backend/internal/handler/peer.go` for the full surface.

3. **Verify** with `nexushub peer list`. Counts should match the
   v1 `wg show wg0 peers`.

A scripted importer that consumes `/etc/wireguard/wg0.conf` is on
the roadmap; until it lands, single-digit peer counts are fast to
type, and three-digit counts are an obvious case for `psql` +
`COPY`.

## Step 4 — Cut over

1. Stop the v1 service: `sudo systemctl stop wg-quick@wg0`.
2. Disable autostart so it doesn't reclaim port 51820 on reboot:
   `sudo systemctl disable wg-quick@wg0`.
3. Start the v2 stack with the production listen port (51820 by
   default; configurable via the interface row).
4. Confirm peers can connect — use the load-test script or just
   reach the dashboard from a remote network.

If v2 misbehaves, swap back: stop v2, re-enable + start
`wg-quick@wg0`. Hold v1 in reserve for at least a week before
deleting the snapshot.

## Step 5 — Decommission v1

Once you've verified peer connectivity for a few days:

```sh
sudo systemctl stop wg-quick@wg0
sudo systemctl disable wg-quick@wg0
sudo apt purge wireguard-tools          # only if v2 doesn't need it on the host
sudo rm -rf /etc/wireguard/             # back this up first if you're not sure
# Remove the v1 service files:
sudo rm /etc/systemd/system/wg-server-*.service /usr/local/bin/wg-server-*
```

The `wg-server-install.sh` and `example.html` legacy files were
removed from the v2 repository in commit `92379b5`; if you have
local clones from before, they're harmless to delete.

## What to read next

- [User guide](./user-guide/README.md) — day-to-day admin tasks.
- [Deployment guide](./deployment/README.md) — production config.
- [Backup + restore](./deployment/backup-restore.md) — protect
  your new deployment from accidental loss.
- [API reference](./api/index.html) — automate everything the UI
  exposes, and a few things it doesn't.

## Reporting issues

If something blocks the migration that this guide doesn't cover,
[open an issue](https://github.com/tomeksdev/NexusHub/issues) with
the `migration` label. Include your v1 version (commit hash from
the old repo if you have it), the v2 version you're targeting, and
what step the problem appeared at.
