// NexusHub k6 baseline. Exercises the three hot paths that dominate
// production traffic:
//
//   1. /auth/refresh — token lifecycle (every 15 min per client).
//   2. /peers?interface_id=… — dashboard auto-refresh (every 10 s
//      per operator browser tab).
//   3. /metrics — Prometheus scrape (every 15 s per scrape target).
//
// Run:
//   k6 run -e NEXUSHUB_URL=https://nexushub.example.com \
//          -e NEXUSHUB_EMAIL=admin@example.com \
//          -e NEXUSHUB_PASSWORD=secret \
//          tests/load/baseline.js
//
// Thresholds encode the SLO we want to hold in production. A failing
// run means either the target deployment needs investigation or the
// SLO is wrong — bump the threshold deliberately if the latter, file
// an issue if the former.

import http from 'k6/http';
import { check, sleep, fail } from 'k6';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.NEXUSHUB_URL || 'http://localhost:8080';
const EMAIL = __ENV.NEXUSHUB_EMAIL || 'admin@example.com';
const PASSWORD = __ENV.NEXUSHUB_PASSWORD;

if (!PASSWORD) {
  fail('NEXUSHUB_PASSWORD must be set');
}

// Custom trend metrics so each endpoint's P95 is attributable
// separately in the summary.
const refreshLatency = new Trend('refresh_latency', true);
const peerListLatency = new Trend('peer_list_latency', true);
const metricsLatency = new Trend('metrics_latency', true);

export const options = {
  scenarios: {
    ramp: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 20 }, // warm up
        { duration: '2m', target: 20 }, // hold baseline
        { duration: '30s', target: 50 }, // peak
        { duration: '1m', target: 50 }, // hold peak
        { duration: '30s', target: 0 }, // cool down
      ],
      gracefulRampDown: '10s',
    },
  },
  // SLO gates. Tune before adding load on a shared environment.
  thresholds: {
    http_req_failed: ['rate<0.01'], // <1% errors
    http_req_duration: ['p(95)<400'], // 95% under 400 ms overall
    refresh_latency: ['p(95)<200'],
    peer_list_latency: ['p(95)<300'],
    metrics_latency: ['p(95)<150'],
  },
  // Summary trend stats — include p(50)/p(95)/p(99) so regressions
  // are obvious without post-processing.
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

// Per-VU state: cache the refresh + access tokens between iterations
// so we don't pay the login cost every loop.
function login() {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } },
  );
  if (res.status !== 200) fail(`login failed: ${res.status} ${res.body}`);
  return res.json();
}

function pickInterface(token) {
  const res = http.get(`${BASE_URL}/api/v1/interfaces?limit=1`, {
    headers: { Authorization: `Bearer ${token}` },
    tags: { name: 'interfaces' },
  });
  if (res.status !== 200) fail(`interfaces: ${res.status}`);
  const body = res.json();
  if (!body.items || body.items.length === 0) fail('no interfaces configured');
  return body.items[0].id;
}

export function setup() {
  const session = login();
  const interfaceID = pickInterface(session.access_token);
  return { interfaceID };
}

export default function (data) {
  const session = login();
  const authHeaders = { Authorization: `Bearer ${session.access_token}` };

  // --- 1. Refresh ---------------------------------------------------------
  {
    const res = http.post(
      `${BASE_URL}/api/v1/auth/refresh`,
      JSON.stringify({ refresh_token: session.refresh_token }),
      { headers: { 'Content-Type': 'application/json' }, tags: { name: 'refresh' } },
    );
    check(res, { 'refresh 200': (r) => r.status === 200 });
    refreshLatency.add(res.timings.duration);
  }

  // --- 2. Peer list -------------------------------------------------------
  {
    const res = http.get(
      `${BASE_URL}/api/v1/peers?interface_id=${data.interfaceID}&limit=50`,
      { headers: authHeaders, tags: { name: 'peers' } },
    );
    check(res, { 'peers 200': (r) => r.status === 200 });
    peerListLatency.add(res.timings.duration);
  }

  // --- 3. Metrics scrape --------------------------------------------------
  {
    const res = http.get(`${BASE_URL}/api/v1/metrics`, {
      headers: authHeaders,
      tags: { name: 'metrics' },
    });
    check(res, { 'metrics 200': (r) => r.status === 200 });
    metricsLatency.add(res.timings.duration);
  }

  // Pace matching realistic per-user iteration rate — an operator's
  // browser isn't hammering the API; each VU doing one loop per
  // ~5 s is closer to real usage than zero-sleep.
  sleep(5);
}
