# Deployment — Observability Starter Kit

Drop-in Grafana dashboard and Prometheus alert rules for the metrics
that the API exports at `GET /api/v1/metrics`.

## Prometheus scrape

Point Prometheus at the API with a label matching the alert rules:

```yaml
scrape_configs:
  - job_name: nexushub
    metrics_path: /api/v1/metrics
    static_configs:
      - targets: ["api.nexushub.example:8080"]
```

The `job="nexushub"` label is what `NexusHubAPIDown` watches.

## Alert rules

`prometheus/alerts.yml` defines ten rules across four groups:

| Group | Alert | Severity |
|---|---|---|
| `nexushub.api` | `NexusHubAPIDown` | page |
| | `NexusHubAPIHighErrorRate` | page |
| | `NexusHubAuthFailuresElevated` | ticket |
| `nexushub.db` | `NexusHubDBPoolExhausted` | page |
| | `NexusHubDBPoolHighWatermark` | ticket |
| `nexushub.wireguard` | `NexusHubWGDeviceDown` | page |
| | `NexusHubWGPeerHandshakeStale` | ticket |
| | `NexusHubWGScrapeErrors` | ticket |
| `nexushub.ebpf` | `NexusHubEBPFScrapeErrors` | ticket |
| | `NexusHubEBPFMapNearCapacity` | ticket |

Load them via the Prometheus config:

```yaml
rule_files:
  - /etc/prometheus/nexushub-alerts.yml
```

## Grafana dashboard

`grafana/nexushub-overview.json` is a 13-panel dashboard split into
API / Database / eBPF / WireGuard sections.

Import it:

1. Grafana → **Dashboards** → **New** → **Import**.
2. Upload `nexushub-overview.json`.
3. Pick your Prometheus datasource when prompted.
4. The `interface` variable auto-populates from
   `label_values(nexushub_wg_peers, interface)` — select the
   interfaces you want to see.

The peer-throughput panel and handshake-freshness table key off the
`public_key` label. Cardinality is O(peers); at typical deployments
(1 interface, ≤ a few thousand peers) Prometheus handles this fine.
