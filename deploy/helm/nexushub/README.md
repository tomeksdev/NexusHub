# NexusHub Helm chart

Helm chart for NexusHub — WireGuard VPN management dashboard with
eBPF security rules.

## Scope

What this chart does:

- Deploys the NexusHub API as a `Deployment`.
- Runs database migrations as a `pre-install` + `pre-upgrade` Helm
  hook `Job`.
- Publishes a `Service` (ClusterIP by default).
- Optionally publishes an `Ingress` you provide TLS for via
  cert-manager or an equivalent.
- Wires secrets from either values (evaluation) or an existing
  `Secret` (production).

What this chart does not do:

- Deploy Postgres. The chart expects an external database —
  managed (RDS / Cloud SQL / Neon / Supabase) or a separately-owned
  in-cluster StatefulSet. Getting Postgres right in Helm is a whole
  chart on its own (HA, backups, upgrades, WAL shipping) and
  tacking it on here would commit operators to an opinion they may
  not share.
- Manage TLS certificates. Bring cert-manager; the chart honours
  `ingress.tls[].secretName`.
- Run the kernel-side WireGuard + eBPF sync. See **Data plane** below.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.13+
- A Postgres 16+ endpoint reachable from the cluster
- Secrets generated out-of-band:

  ```sh
  # 32+ random bytes, base64. Rotate = invalidate every session.
  JWT_SECRET=$(openssl rand -base64 48)

  # Exactly 32 bytes, base64. Rotate = make every stored peer key
  # undecryptable. Back this up separately from the database — a
  # DB backup without this value is useless.
  PEER_KEY_ENCRYPTION_KEY=$(openssl rand -base64 32)
  ```

## Install

### Minimal (evaluation)

```sh
helm install nexushub ./deploy/helm/nexushub \
  --namespace nexushub --create-namespace \
  --set postgres.url="postgres://nexushub:password@pg.example.com:5432/nexushub?sslmode=require" \
  --set secrets.jwtSecret="$JWT_SECRET" \
  --set secrets.peerKeyEncryptionKey="$PEER_KEY_ENCRYPTION_KEY" \
  --set config.wgEndpoint="vpn.example.com:51820"
```

### Production-leaning (externally-managed secrets)

```sh
# One-time secret creation — do this with whatever your
# secret-management story is (external-secrets, sealed-secrets,
# sops + git, kubectl-with-out-of-band-passing-a-vault):
kubectl -n nexushub create secret generic nexushub-app \
  --from-literal=JWT_SECRET="$JWT_SECRET" \
  --from-literal=PEER_KEY_ENCRYPTION_KEY="$PEER_KEY_ENCRYPTION_KEY"

kubectl -n nexushub create secret generic nexushub-postgres \
  --from-literal=DATABASE_URL="$DATABASE_URL"

helm install nexushub ./deploy/helm/nexushub \
  --namespace nexushub \
  --set secrets.existingSecret=nexushub-app \
  --set postgres.existingSecret=nexushub-postgres \
  --values values-prod.yaml
```

With an ingress and cert-manager:

```yaml
# values-prod.yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: nexushub.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: nexushub-tls
      hosts:
        - nexushub.example.com

config:
  wgEndpoint: vpn.example.com:51820

tracing:
  endpoint: otel-collector.observability.svc.cluster.local:4317
  samplerArg: "0.1"
```

## Values

See [`values.yaml`](./values.yaml) — every field is documented
inline. Notable ones:

| Key | Default | Why |
|---|---|---|
| `secrets.existingSecret` | `""` | Preferred for prod. The chart reads `JWT_SECRET` + `PEER_KEY_ENCRYPTION_KEY` from this Secret. |
| `postgres.existingSecret` | `""` | Preferred for prod. The chart reads `DATABASE_URL` from `.postgres.urlKey` inside this Secret. |
| `ingress.enabled` | `false` | Off unless you configure a host + TLS. |
| `migrations.enabled` | `true` | Pre-install/pre-upgrade Job runs `nexushub-api migrate up`. Turn off if you run migrations out-of-band. |
| `dataPlane.enabled` | `false` | See below. Keeps the pod unprivileged by default. |
| `probes.startup.failureThreshold` | `30` | 30 × 5 s = 2.5 min grace. Bump for slow migrations. |

## Data plane

Kernel-side WireGuard + eBPF sync needs `hostNetwork: true` plus
`CAP_NET_ADMIN` / `CAP_BPF` / `CAP_NET_RAW` — the pod can
reconfigure the host network and attach XDP programs to physical
NICs. Effectively root on the node.

This chart leaves that off by default. The common patterns are:

1. **API-only in k8s, kernel plane on hosts** (recommended).
   NexusHub writes peer + rule state to the database. A separate
   `systemd` unit on each WireGuard host (see
   `deploy/systemd/nexushub-api.service`) reads from the same DB
   and applies the kernel state. The k8s pod stays unprivileged.

2. **All-in-one DaemonSet** (power users). Set
   `dataPlane.enabled: true` to flip on hostNetwork + the
   capability set. Run as a DaemonSet on the subset of nodes that
   should serve as WireGuard endpoints (`nodeSelector` or a
   taint/toleration pair).

If you're not sure which pattern fits, pick (1).

## Upgrade

```sh
helm upgrade nexushub ./deploy/helm/nexushub \
  --namespace nexushub \
  --reuse-values \
  --set image.tag=v2.0.1
```

The pre-upgrade Job runs migrations before the Deployment rolls.
A failed migration leaves the previous ReplicaSet serving traffic
(the Job is a hook — its failure halts the upgrade). Fix the
migration, rerun `helm upgrade`.

## Uninstall

```sh
helm uninstall nexushub --namespace nexushub
```

The app Secret and Postgres Secret are annotated with
`helm.sh/resource-policy: keep` and survive `uninstall`. That's
deliberate: losing `PEER_KEY_ENCRYPTION_KEY` makes every stored
peer key undecryptable, and no `helm uninstall` should ever do
that. Delete the Secrets manually only when you are certain you
never want to restore the DB backup.

## Troubleshooting

**Pod in `ImagePullBackOff`.** Check `image.pullSecrets` — GHCR
images require a pull secret for private repos.

**Migration Job fails.** `kubectl logs job/nexushub-migrate-<rev>`
in the release namespace. Common cause: `DATABASE_URL` points at a
DB the pod can't reach (network policy, sslmode mismatch). The app
Deployment stays on the previous revision; the chart won't proceed
until migrations land.

**API pod `CrashLoopBackOff` with "no such secret".** One of
`JWT_SECRET` or `PEER_KEY_ENCRYPTION_KEY` is empty. The chart
errors at `helm install` time for that case, so this only happens
if you edited the rendered manifest directly — re-run
`helm upgrade --install`.

## What's missing (known)

- NetworkPolicy — worth adding when the chart is used as a child
  chart of a broader platform; scope-out today.
- HorizontalPodAutoscaler — the API is largely DB-bound, so HPA
  on CPU isn't the right signal. Custom-metric HPA (request rate)
  is the right answer when it matters.
- Prometheus `ServiceMonitor` — the API exposes `/api/v1/metrics`
  but the chart doesn't ship a scrape config. Works with a
  Prometheus that does endpoint-label-based discovery.
