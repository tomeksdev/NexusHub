import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { useNowEveryMinute } from "../lib/hooks";
import { sseStream } from "../lib/sse";
import { PeerConfigModal } from "./PeerConfigModal";
import { PeerCreateModal } from "./PeerCreateModal";

interface Peer {
  id: string;
  interface_id: string;
  name: string;
  public_key: string;
  assigned_ip: string;
  status: string;
  last_handshake?: string | null;
  rx_bytes: number;
  tx_bytes: number;
  created_at: string;
}

// Live state keyed by public key. We merge this over the DB-sourced peer
// list so the table reflects real handshakes/traffic without refetching.
interface LivePeer {
  last_handshake: string;
  rx_bytes: number;
  tx_bytes: number;
}

interface SsePayload {
  interface: string;
  public_key: string;
  last_handshake: string;
  rx_bytes: number;
  tx_bytes: number;
}

export function PeersPage() {
  const qc = useQueryClient();
  const nowMs = useNowEveryMinute();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["peers"],
    queryFn: async () => {
      // The /peers list endpoint requires interface_id. For now we
      // fetch the first location and display peers for it; a real
      // multi-location UI would render a dropdown.
      const ifaces = await api<
        PageEnvelope<{ id: string; name: string }>
      >("/api/v1/interfaces?limit=1");
      if (ifaces.items.length === 0)
        return { items: [], total: 0, ifaceID: null, ifaceName: null };
      const iface = ifaces.items[0];
      const peers = await api<PageEnvelope<Peer>>(
        `/api/v1/peers?interface_id=${iface.id}&limit=100`,
      );
      return {
        items: peers.items,
        total: peers.total,
        ifaceID: iface.id,
        ifaceName: iface.name,
      };
    },
  });

  const [live, setLive] = useState<Record<string, LivePeer>>({});
  const [configPeer, setConfigPeer] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      api(`/api/v1/peers/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["peers"] }),
  });

  function onDelete(p: Peer) {
    if (!confirm(`Delete peer "${p.name}"? This revokes the VPN credentials.`))
      return;
    deleteMut.mutate(p.id);
  }

  useEffect(() => {
    const ctrl = new AbortController();
    sseStream("/api/v1/peers/events", {
      signal: ctrl.signal,
      onEvent: (event, raw) => {
        if (event === "ping") return;
        try {
          const payload = JSON.parse(raw) as SsePayload | SsePayload[] | null;
          // The backend may send `data: null` for an empty snapshot
          // (Go's nil slice marshals to JSON null, not []). Normalize
          // both that and any null entries that slip through.
          const arr =
            payload == null
              ? []
              : Array.isArray(payload)
                ? payload
                : [payload];
          const list = arr.filter(
            (p): p is SsePayload =>
              p != null && typeof p.public_key === "string",
          );
          if (list.length === 0) return;
          setLive((prev) => {
            const next = { ...prev };
            for (const p of list) {
              next[p.public_key] = {
                last_handshake: p.last_handshake,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
              };
            }
            return next;
          });
        } catch {
          // Malformed frame — ignore rather than tear down the stream.
        }
      },
    });
    return () => ctrl.abort();
  }, []);

  if (isLoading)
    return <div className="p-6 text-muted">Loading peers…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const items = data?.items ?? [];
  const onlineCount = items.filter((p) => {
    const l = live[p.public_key];
    const handshake = l?.last_handshake ?? p.last_handshake;
    if (!handshake || isZeroTime(handshake)) return false;
    return nowMs - new Date(handshake).getTime() < 3 * 60_000;
  }).length;
  const totalRx = items.reduce(
    (sum, p) => sum + (live[p.public_key]?.rx_bytes ?? p.rx_bytes),
    0,
  );
  const totalTx = items.reduce(
    (sum, p) => sum + (live[p.public_key]?.tx_bytes ?? p.tx_bytes),
    0,
  );

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Peers</h1>
        <div className="topbar-actions">
          {data?.ifaceName && (
            <span className="text-muted text-sm">
              location:{" "}
              <span className="text-faint font-mono">{data.ifaceName}</span>
            </span>
          )}
          {data?.ifaceID && (
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="btn-primary"
            >
              + New peer
            </button>
          )}
        </div>
      </div>

      <div className="stats-row">
        <div className="stat-card">
          <span className="stat-label">Peers</span>
          <span className="stat-value">{items.length}</span>
        </div>
        <div className="stat-card success">
          <span className="stat-label">Online (3 min)</span>
          <span className="stat-value">{onlineCount}</span>
        </div>
        <div className="stat-card warning">
          <span className="stat-label">Total RX</span>
          <span className="stat-value">{formatBytes(totalRx)}</span>
        </div>
        <div className="stat-card danger">
          <span className="stat-label">Total TX</span>
          <span className="stat-value">{formatBytes(totalTx)}</span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="panel">
          <p className="text-muted">No peers yet.</p>
        </div>
      ) : (
        <div className="data-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Assigned IP</th>
                <th>Status</th>
                <th>Last handshake</th>
                <th>RX / TX</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((p) => {
                const l = live[p.public_key];
                const handshake = l?.last_handshake ?? p.last_handshake;
                const rx = l?.rx_bytes ?? p.rx_bytes;
                const tx = l?.tx_bytes ?? p.tx_bytes;
                const recentMs =
                  handshake && !isZeroTime(handshake)
                    ? nowMs - new Date(handshake).getTime()
                    : Number.POSITIVE_INFINITY;
                const isLive = recentMs < 3 * 60_000;
                return (
                  <tr key={p.id}>
                    <td className="font-medium">
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
                        {p.name}
                      </span>
                    </td>
                    <td className="font-mono text-muted">{p.assigned_ip}</td>
                    <td>
                      <span className={statusClass(p.status)}>{p.status}</span>
                    </td>
                    <td className="text-muted">
                      {handshake && !isZeroTime(handshake)
                        ? new Date(handshake).toLocaleString()
                        : "—"}
                    </td>
                    <td className="text-muted font-mono text-xs">
                      {formatBytes(rx)} / {formatBytes(tx)}
                    </td>
                    <td className="text-right">
                      <div className="inline-flex gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setConfigPeer({ id: p.id, name: p.name })
                          }
                          className="btn-ghost"
                        >
                          Config
                        </button>
                        <button
                          type="button"
                          onClick={() => onDelete(p)}
                          disabled={deleteMut.isPending}
                          className="btn-danger"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {configPeer && (
        <PeerConfigModal
          peerId={configPeer.id}
          peerName={configPeer.name}
          onClose={() => setConfigPeer(null)}
        />
      )}
      {showCreate && data?.ifaceID && (
        <PeerCreateModal
          interfaceID={data.ifaceID}
          onClose={() => setShowCreate(false)}
          onCreated={(peer) => {
            setShowCreate(false);
            setConfigPeer({ id: peer.id, name: peer.name });
          }}
        />
      )}
    </div>
  );
}

function statusClass(s: string): string {
  switch (s) {
    case "active":
    case "enabled":
      return "status-badge ok";
    case "expired":
      return "status-badge warning";
    case "revoked":
    case "disabled":
      return "status-badge critical";
    default:
      return "status-badge muted";
  }
}

function isZeroTime(s: string): boolean {
  return s.startsWith("0001-");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
