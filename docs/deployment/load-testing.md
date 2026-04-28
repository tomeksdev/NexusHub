# Load testing

`tests/load/baseline.js` is a [k6](https://k6.io/) script that
drives the three endpoints that dominate production traffic:

| Endpoint | Per-user cadence | Why it's hot |
|---|---|---|
| `POST /api/v1/auth/refresh` | every 15 min | Access token expiry |
| `GET /api/v1/peers?interface_id=…` | every 10 s | Dashboard auto-refresh |
| `GET /api/v1/metrics` | every 15 s | Prometheus scrape |

## Running

```sh
k6 run \
  -e NEXUSHUB_URL=https://nexushub.example.com \
  -e NEXUSHUB_EMAIL=admin@example.com \
  -e NEXUSHUB_PASSWORD="$NEXUSHUB_PASSWORD" \
  tests/load/baseline.js
```

The ramp profile is 20 VUs baseline → 50 VUs peak over ~5 minutes.
One VU ≈ one browser session; 50 concurrent operators is generous
for a VPN admin panel.

## Baseline SLOs

The script's `thresholds` block encodes the targets we commit to
hold in production. A failing run means either the target
deployment needs investigation or the SLO is wrong — bump the
threshold deliberately if the latter, file an issue if the former.

| Metric | Target |
|---|---|
| `http_req_failed` | <1% |
| `http_req_duration` (p95) | <400 ms |
| `refresh_latency` (p95) | <200 ms |
| `peer_list_latency` (p95) | <300 ms |
| `metrics_latency` (p95) | <150 ms |

Targets assume:

- Backend and Postgres on the same host (or low-latency LAN).
- Postgres pool at the default 25 max connections.
- No eBPF rule maps full (the reconciler has the map-full signal
  on the Prometheus dashboard; watch `nexushub_ebpf_map_entries /
  nexushub_ebpf_map_capacity`).

## Regression hunting

`summaryTrendStats` is set to `avg, min, med, p(95), p(99), max`,
so a regression shows up as a shifted p95/p99 without needing to
post-process the CSV. Capture the summary output in CI (or a
periodic job) and diff against the last green run to catch drift
before users notice.

## What this doesn't cover

- **Auth lockout behaviour** — the script uses one shared account;
  the 5-failure lockout is not exercised.
- **WebSocket / SSE streams** — `/api/v1/peers/events` stays open
  for the length of a tab's lifetime; k6 doesn't model that here.
  A separate soak test is the right tool if you need to validate
  SSE memory behaviour.
- **eBPF hot path** — load landing on the API via XDP/TC hooks is
  kernel-side behaviour that a user-space k6 cannot measure. Use
  `iperf3` through the tunnel or `bpftool prog profile` for that.
