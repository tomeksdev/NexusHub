import { useQuery } from "@tanstack/react-query";

import { api } from "../lib/api";
import { useNowEveryMinute } from "../lib/hooks";

interface DashboardCounts {
  locations: number;
  users: number;
  peers: number;
  peers_online: number;
}

interface DashboardPeer {
  public_key: string;
  interface: string;
  owner_username?: string;
  owner_email?: string;
  last_handshake: string;
  rx_bytes: number;
  tx_bytes: number;
}

interface DashboardLocation {
  name: string;
  listen_port: number;
  live: boolean;
  peers_total: number;
  peers_online: number;
}

interface DashboardResponse {
  counts: DashboardCounts;
  top_peers: DashboardPeer[];
  locations: DashboardLocation[];
  generated_at: string;
}

export function DashboardPage() {
  const nowMs = useNowEveryMinute();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardResponse>("/api/v1/dashboard"),
    // 5-second refresh keeps the live counts in sync with the backend
    // peer-stats poller without hammering. The page already feels
    // real-time at this cadence on a typical install.
    refetchInterval: 5_000,
    refetchOnWindowFocus: true,
  });

  if (isLoading)
    return <div className="p-6 text-muted">Loading dashboard…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const counts = data?.counts ?? {
    locations: 0,
    users: 0,
    peers: 0,
    peers_online: 0,
  };

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Dashboard</h1>
        {data?.generated_at && (
          <span className="text-faint text-xs font-mono">
            updated {new Date(data.generated_at).toLocaleTimeString()}
          </span>
        )}
      </div>

      <div className="stats-row">
        <Stat label="Locations" value={counts.locations} />
        <Stat label="Users" value={counts.users} tone="success" />
        <Stat label="Peers" value={counts.peers} tone="warning" />
        <Stat
          label="Online (3 min)"
          value={counts.peers_online}
          tone={counts.peers_online > 0 ? "success" : "danger"}
        />
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <section className="panel">
          <div className="panel-header">
            <span className="panel-title">Active locations</span>
            <span className="text-faint text-xs">
              {(data?.locations ?? []).filter((l) => l.live).length}/
              {(data?.locations ?? []).length} up
            </span>
          </div>
          {(data?.locations ?? []).length === 0 ? (
            <p className="text-muted">No locations configured.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-muted text-left">
                  <th className="py-2 font-medium">Name</th>
                  <th className="py-2 font-medium">Port</th>
                  <th className="py-2 font-medium">State</th>
                  <th className="py-2 font-medium text-right">Online / Total</th>
                </tr>
              </thead>
              <tbody>
                {(data?.locations ?? []).map((l) => (
                  <tr
                    key={l.name}
                    className="border-t border-[var(--color-line)]"
                  >
                    <td className="py-2 font-medium">{l.name}</td>
                    <td className="py-2 text-muted font-mono">
                      {l.listen_port}
                    </td>
                    <td className="py-2">
                      {l.live ? (
                        <span className="status-badge ok">
                          <span className="dot" />
                          UP
                        </span>
                      ) : (
                        <span className="status-badge muted">
                          <span className="dot" />
                          DOWN
                        </span>
                      )}
                    </td>
                    <td className="py-2 text-right">
                      <span className="text-success font-semibold">
                        {l.peers_online}
                      </span>
                      <span className="text-faint"> / {l.peers_total}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <span className="panel-title">Top peers by traffic</span>
            <span className="text-faint text-xs">RX + TX cumulative</span>
          </div>
          {(data?.top_peers ?? []).length === 0 ? (
            <p className="text-muted">No active peers yet.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-muted text-left">
                  <th className="py-2 font-medium">Owner</th>
                  <th className="py-2 font-medium">Location</th>
                  <th className="py-2 font-medium">Last handshake</th>
                  <th className="py-2 font-medium text-right">RX / TX</th>
                </tr>
              </thead>
              <tbody>
                {(data?.top_peers ?? []).map((p) => {
                  const recentMs =
                    p.last_handshake && !p.last_handshake.startsWith("0001-")
                      ? nowMs - new Date(p.last_handshake).getTime()
                      : Number.POSITIVE_INFINITY;
                  const isLive = recentMs < 60_000;
                  return (
                    <tr
                      key={p.public_key}
                      className="border-t border-[var(--color-line)]"
                    >
                      <td className="py-2">
                        {p.owner_username || p.owner_email ? (
                          <span title={p.owner_email ?? undefined}>
                            {p.owner_username || p.owner_email}
                          </span>
                        ) : (
                          <span className="text-faint">unassigned</span>
                        )}
                      </td>
                      <td className="py-2 text-muted">{p.interface}</td>
                      <td className="py-2 text-muted">
                        {p.last_handshake &&
                        !p.last_handshake.startsWith("0001-") ? (
                          <span className="inline-flex items-center gap-2">
                            <span
                              aria-hidden
                              className="inline-block w-1.5 h-1.5 rounded-full"
                              style={{
                                background: isLive
                                  ? "var(--color-success)"
                                  : "var(--color-faint)",
                              }}
                            />
                            {new Date(p.last_handshake).toLocaleTimeString()}
                          </span>
                        ) : (
                          <span className="text-faint">never</span>
                        )}
                      </td>
                      <td className="py-2 text-right text-muted font-mono text-xs">
                        {formatBytes(p.rx_bytes)} / {formatBytes(p.tx_bytes)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  tone = "primary",
}: {
  label: string;
  value: number;
  tone?: "primary" | "success" | "warning" | "danger";
}) {
  const cls = tone === "primary" ? "stat-card" : `stat-card ${tone}`;
  return (
    <div className={cls}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
