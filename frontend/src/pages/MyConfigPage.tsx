import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PeerConfigModal } from "./PeerConfigModal";

// MyConfigPage is the user-role landing page. Lists the
// authenticated user's own peers using the /me/peers surface that
// enforces ownership server-side, and offers config download + QR
// for each one. No admin actions (no Edit, no Delete, no Rotate
// PSK) — those flows live on the admin side.

interface MyPeer {
  id: string;
  interface_id: string;
  name: string;
  description?: string | null;
  assigned_ip: string;
  allowed_ips: string[];
  client_allowed_ips: string[];
  endpoint?: string | null;
  persistent_keepalive?: number | null;
  status: string;
  last_handshake?: string | null;
  rx_bytes: number;
  tx_bytes: number;
}

interface IfaceLite {
  id: string;
  name: string;
  endpoint?: string | null;
}

export function MyConfigPage() {
  const { email } = useAuth();
  const [configPeer, setConfigPeer] = useState<{
    id: string;
    name: string;
  } | null>(null);

  const peersQ = useQuery({
    queryKey: ["me-peers"],
    queryFn: () => api<PageEnvelope<MyPeer>>("/api/v1/me/peers?limit=100"),
    // 10 s refresh so a user reconnecting their WireGuard client
    // sees the status flip from Not connected to Connected
    // without manually reloading. Backend WG stats poller writes
    // at 30 s; 10 s here catches a freshly-written row within a
    // tick.
    refetchInterval: 10_000,
    refetchOnWindowFocus: true,
  });
  // Best-effort interface lookup so we can show the location name
  // for each peer. Users don't have admin access to /interfaces;
  // we silently fall back to displaying the raw interface id slice
  // when the request 403s.
  const ifacesQ = useQuery({
    queryKey: ["interfaces-mine-readonly"],
    queryFn: () =>
      api<PageEnvelope<IfaceLite>>("/api/v1/interfaces?limit=100"),
    retry: false,
    staleTime: 60_000,
  });
  const ifaceByID = new Map<string, IfaceLite>();
  for (const i of ifacesQ.data?.items ?? []) ifaceByID.set(i.id, i);

  const peers = peersQ.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">My Config</h1>
        <span className="text-muted text-sm">
          Signed in as <span className="font-mono">{email ?? "—"}</span>
        </span>
      </div>

      {peersQ.isLoading ? (
        <p className="text-muted">Loading…</p>
      ) : peersQ.isError ? (
        <div className="panel">
          <p className="text-danger">
            Failed to load: {(peersQ.error as Error).message}
          </p>
        </div>
      ) : peers.length === 0 ? (
        <div className="panel">
          <p className="text-muted">
            No VPN configurations assigned to your account yet. Ask an
            administrator to create a peer for you.
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {peers.map((p) => {
            const iface = ifaceByID.get(p.interface_id);
            const connected = isLiveHandshake(p.last_handshake);
            return (
              <section key={p.id} className="panel">
                <div className="panel-header">
                  <div>
                    <span className="panel-title">{p.name}</span>
                    {p.description && (
                      <p className="text-faint text-xs mt-0.5">
                        {p.description}
                      </p>
                    )}
                  </div>
                  <ConnectionBadge
                    connected={connected}
                    enabled={p.status !== "disabled"}
                  />
                </div>
                <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
                  <dt className="text-muted">Location</dt>
                  <dd className="font-mono">
                    {iface?.name ?? (
                      <span className="text-faint">
                        {p.interface_id.slice(0, 8)}
                      </span>
                    )}
                  </dd>
                  <dt className="text-muted">Assigned IP</dt>
                  <dd className="font-mono">{p.assigned_ip}/32</dd>
                  <dt className="text-muted">Endpoint</dt>
                  <dd className="font-mono">
                    {p.endpoint ?? iface?.endpoint ?? (
                      <span className="text-faint">(inherited)</span>
                    )}
                  </dd>
                  <dt className="text-muted">Allowed networks</dt>
                  <dd className="font-mono text-xs">
                    {p.client_allowed_ips.length > 0
                      ? p.client_allowed_ips.join(", ")
                      : (
                        <span className="text-faint">
                          (location default)
                        </span>
                      )}
                  </dd>
                  <dt className="text-muted">Last handshake</dt>
                  <dd className="text-muted">
                    {handshakeRelative(p.last_handshake)}
                  </dd>
                  <dt className="text-muted">Traffic</dt>
                  <dd className="text-muted font-mono text-xs">
                    {formatBytes(p.rx_bytes)} received ·{" "}
                    {formatBytes(p.tx_bytes)} sent
                  </dd>
                </dl>
                <div className="mt-4 flex gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setConfigPeer({ id: p.id, name: p.name })
                    }
                    className="btn-primary"
                  >
                    Show config + QR
                  </button>
                  <a
                    href={`/api/v1/me/peers/${p.id}/config`}
                    download={`${p.name || "peer"}.conf`}
                    className="btn-ghost"
                  >
                    Download .conf
                  </a>
                </div>
              </section>
            );
          })}
        </div>
      )}

      {configPeer && (
        <PeerConfigModal
          peerId={configPeer.id}
          peerName={configPeer.name}
          // No onEdit — users can't edit their own peer's
          // server-side settings.
          onClose={() => setConfigPeer(null)}
          // The default PeerConfigModal fetches via /peers/:id/config
          // which is admin-only. Override the API base path so the
          // /me equivalent is used instead.
          configPathOverride={`/api/v1/me/peers/${configPeer.id}`}
        />
      )}
    </div>
  );
}

// ConnectionBadge tells the user whether their tunnel is alive.
// "Connected" requires both an enabled peer AND a recent
// handshake (round-9: previously we only rendered the static DB
// status, which was useless for a user trying to confirm their VPN
// is talking). Disabled peers stay shown as such regardless of
// handshake age.
function ConnectionBadge({
  connected,
  enabled,
}: {
  connected: boolean;
  enabled: boolean;
}) {
  if (!enabled) {
    return (
      <span className="status-badge muted">
        <span className="dot" />
        DISABLED
      </span>
    );
  }
  if (connected) {
    return (
      <span className="status-badge ok">
        <span className="dot" />
        CONNECTED
      </span>
    );
  }
  return (
    <span className="status-badge muted">
      <span className="dot" />
      NOT CONNECTED
    </span>
  );
}

// 3 minutes matches the round-1 PeersPage threshold the admin side
// uses for the "live" dot — keep both surfaces aligned so an admin
// and a user looking at the same peer see consistent state.
function isLiveHandshake(last?: string | null): boolean {
  if (!last || last.startsWith("0001-")) return false;
  return Date.now() - new Date(last).getTime() < 3 * 60_000;
}

// handshakeRelative renders the handshake age in human words via
// Intl.RelativeTimeFormat so "42 seconds ago" / "5 minutes ago"
// fall out without a date library. Returns "Never" when the peer
// has never handshaken.
function handshakeRelative(last?: string | null): string {
  if (!last || last.startsWith("0001-")) return "Never";
  const diffMs = Date.now() - new Date(last).getTime();
  const sec = Math.round(diffMs / 1000);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (sec < 60) return rtf.format(-sec, "second");
  const min = Math.round(sec / 60);
  if (min < 60) return rtf.format(-min, "minute");
  const hr = Math.round(min / 60);
  if (hr < 24) return rtf.format(-hr, "hour");
  const day = Math.round(hr / 24);
  return rtf.format(-day, "day");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}
