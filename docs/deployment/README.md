# Deployment guide

Three supported deployment shapes. Pick whichever fits your
operational story; you can switch later (the database is the only
piece of state, and `scripts/backup.sh` makes a clean dump).

| Target | When to use it | Entry point |
|---|---|---|
| Docker Compose | Single host, fast iteration, Caddy + ACME for TLS | [`docker/docker-compose.prod.yml`](../../docker/docker-compose.prod.yml) |
| Bare-metal / VM | Single host, no Docker, system-managed Postgres + WireGuard | [`scripts/install.sh`](../../scripts/install.sh) |
| Kubernetes (Helm) | Cluster, externally-managed Postgres, GitOps-friendly | [`deploy/helm/nexushub/README.md`](../../deploy/helm/nexushub/README.md) |

Common to all three:

- An operator-supplied Postgres 16+. The chart and compose stack
  ship without an embedded database — getting Postgres right (HA,
  backups, upgrades) is its own concern.
- Two secrets generated out-of-band:

  ```sh
  JWT_SECRET=$(openssl rand -base64 48)            # 32+ random bytes
  PEER_KEY_ENCRYPTION_KEY=$(openssl rand -base64 32) # exactly 32 bytes
  ```

  `PEER_KEY_ENCRYPTION_KEY` encrypts WireGuard private keys + TOTP
  secrets at rest. **Losing it makes the database backup useless**
  for restoring peer configs. Back it up separately.

## 1. Docker Compose

Best for single-host installs with TLS and a low-friction
operator experience. The stack runs four containers: Postgres,
the API, a one-shot init container that copies the SPA bundle out
of the API image into a shared volume, and Caddy terminating TLS
with auto-provisioned ACME certificates.

```sh
cp docker/.env.example docker/.env
# edit docker/.env — fill in NEXUSHUB_HOST, POSTGRES_PASSWORD,
# JWT_SECRET, PEER_KEY_ENCRYPTION_KEY, WG_ENDPOINT
docker compose -f docker/docker-compose.prod.yml up -d
```

Point DNS at the host **before** the first start so Caddy can
satisfy the HTTP-01 challenge. The Caddyfile is tuned for SPA
deep-links (try_files fallback to index.html) and aggressive cache
headers on content-hashed `/assets/*`.

Migrations run automatically on first API start via the embedded
`/app/nexushub-migrate up` invocation. Seed the first admin with
the `nexushub-seed` binary that ships in the same image:

```sh
docker compose -f docker/docker-compose.prod.yml exec \
  -e NEXUSHUB_ADMIN_EMAIL=admin@example.com \
  -e NEXUSHUB_ADMIN_USERNAME=admin \
  -e NEXUSHUB_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  api /app/nexushub-seed
```

## 2. Bare-metal install

For operators who run WireGuard on the host already and want
NexusHub to manage it without Docker in the picture.

```sh
curl -fsSL https://raw.githubusercontent.com/tomeksdev/NexusHub/main/scripts/install.sh \
  | sudo NEXUSHUB_VERSION=v2.0.0 bash
```

What the script does (idempotent — re-running upgrades the binary
without touching `/etc/nexushub/env`):

- Installs `postgresql`, `wireguard-tools`, `iproute2`, `curl` via
  apt (Debian/Ubuntu only; amd64 + arm64).
- Creates the `nexushub` system user + state/log/config dirs with
  0o700/0o750/0o750 permissions.
- Bootstraps an empty Postgres database + role.
- Downloads the GitHub release tarball for the requested tag and
  installs `/usr/local/bin/nexushub-api`.
- Drops the systemd unit + `/etc/nexushub/env` template.
- Enables (but does not start) the unit.

Then:

```sh
sudo $EDITOR /etc/nexushub/env       # fill in the secrets
sudo -u nexushub /usr/local/bin/nexushub-api migrate up
sudo -u nexushub /usr/local/bin/nexushub-api seed   # NEXUSHUB_ADMIN_* in env
sudo systemctl start nexushub-api
```

The unit runs as `nexushub:nexushub` with `AmbientCapabilities=
CAP_NET_ADMIN+CAP_BPF+CAP_NET_RAW`, `ProtectSystem=strict`,
`ProtectHome=yes`, and a 20 s graceful SIGTERM window matching
the API's own shutdown timeout.

You'll likely front it with nginx or Caddy on the host for TLS;
the unit listens on `127.0.0.1:8080` by default (override via
`PORT` in the env file).

## 3. Helm (Kubernetes)

For multi-tenant clusters and GitOps shops. The chart deploys the
API only; bring your own Postgres (managed service or in-cluster
StatefulSet you own separately).

```sh
helm install nexushub ./deploy/helm/nexushub \
  --namespace nexushub --create-namespace \
  --set postgres.url="postgres://nexushub:pw@db:5432/nexushub?sslmode=require" \
  --set secrets.jwtSecret="$JWT_SECRET" \
  --set secrets.peerKeyEncryptionKey="$PEER_KEY_ENCRYPTION_KEY"
```

Production deployments should pre-create Secrets and reference
them via `secrets.existingSecret` + `postgres.existingSecret`.
Full values reference + ingress / cert-manager / dataPlane
guidance in
[`deploy/helm/nexushub/README.md`](../../deploy/helm/nexushub/README.md).

The chart leaves kernel-side WireGuard + eBPF sync **off** by
default (`dataPlane.enabled: false`). Enabling it requires
`hostNetwork` + privileged caps — effectively root on the node.
The recommended pattern is **API in k8s + systemd unit on the
WireGuard hosts** for clusters that need both the management plane
and the data plane.

## Day-2 operations

| Topic | Doc |
|---|---|
| Backup + restore + DR drill | [backup-restore.md](./backup-restore.md) |
| Prometheus + Grafana + alerts | [observability.md](./observability.md) |
| Load testing baseline | [load-testing.md](./load-testing.md) |

## Choosing a tag

`latest` tracks the most recent push to `main`. Production should
pin to a semver tag — both the Docker image and the Helm chart
honour the version you supply, and `goreleaser` produces signed
release artefacts on every tag push.
