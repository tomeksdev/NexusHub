import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { useNowEveryMinute } from "../lib/hooks";
import { PeerConfigModal } from "./PeerConfigModal";
import { PeerCreateModal } from "./PeerCreateModal";
import { PeerEditModal, type EditablePeer } from "./PeerEditModal";

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  is_active: boolean;
  totp_enabled: boolean;
  last_login_at?: string | null;
  created_at: string;
}

interface Peer {
  id: string;
  interface_id: string;
  owner_user_id?: string | null;
  name: string;
  description?: string | null;
  public_key: string;
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

interface Iface {
  id: string;
  name: string;
}

interface Props {
  userID: string;
  onBack: () => void;
}

export function UserDetailPage({ userID, onBack }: Props) {
  const qc = useQueryClient();
  const nowMs = useNowEveryMinute();
  const [configPeer, setConfigPeer] = useState<{
    id: string;
    name: string;
  } | null>(null);
  const [editPeer, setEditPeer] = useState<EditablePeer | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  // Per-peer version counter — bumped on edit save and used as the
  // React key on PeerConfigModal so the operator never sees a
  // stale .conf after editing. Mirrors the PeersPage pattern.
  const [peerVersions, setPeerVersions] = useState<Record<string, number>>({});
  function bumpVersion(id: string) {
    setPeerVersions((prev) => ({ ...prev, [id]: (prev[id] ?? 0) + 1 }));
  }

  function toEditable(p: Peer): EditablePeer {
    return {
      id: p.id,
      interface_id: p.interface_id,
      owner_user_id: p.owner_user_id,
      name: p.name,
      description: p.description ?? null,
      allowed_ips: p.allowed_ips ?? [],
      client_allowed_ips: p.client_allowed_ips ?? [],
      assigned_ip: p.assigned_ip,
      endpoint: p.endpoint ?? null,
      persistent_keepalive: p.persistent_keepalive ?? null,
      status: p.status,
    };
  }

  const userQ = useQuery({
    queryKey: ["user", userID],
    queryFn: () => api<User>(`/api/v1/users/${userID}`),
  });

  const peersQ = useQuery({
    queryKey: ["peers-by-owner", userID],
    queryFn: () =>
      api<PageEnvelope<Peer>>(
        `/api/v1/peers?owner_user_id=${userID}&limit=200`,
      ),
  });

  // Build an interface_id → name lookup so the table can render the
  // location each peer belongs to without one fetch per peer.
  const ifacesQ = useQuery({
    queryKey: ["interfaces"],
    queryFn: () => api<PageEnvelope<Iface>>("/api/v1/interfaces?limit=100"),
    staleTime: 60_000,
  });
  const ifaceByID = new Map<string, Iface>();
  for (const i of ifacesQ.data?.items ?? []) ifaceByID.set(i.id, i);

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      api(`/api/v1/peers/${id}`, { method: "DELETE" }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["peers-by-owner", userID] }),
  });

  const peers = peersQ.data?.items ?? [];
  // Default location for "Add peer" — first interface, since the user
  // doesn't have a "preferred" location stored anywhere yet.
  const defaultIfaceID = ifacesQ.data?.items[0]?.id ?? "";

  return (
    <div className="space-y-6">
      <div className="topbar">
        <div className="flex items-center gap-3">
          <button type="button" onClick={onBack} className="btn-ghost">
            ← Users
          </button>
          <h1 className="page-title">{userQ.data?.username ?? "User"}</h1>
        </div>
        <div className="topbar-actions">
          {defaultIfaceID && (
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="btn-primary"
            >
              + Add peer
            </button>
          )}
        </div>
      </div>

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">Profile</span>
          {userQ.data && !userQ.data.is_active && (
            <span className="status-badge muted">
              <span className="dot" />
              DISABLED
            </span>
          )}
        </div>
        {userQ.isLoading ? (
          <p className="text-muted">Loading…</p>
        ) : userQ.isError ? (
          <p className="text-danger">{(userQ.error as Error).message}</p>
        ) : (
          <dl className="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
            <dt className="text-muted">Email</dt>
            <dd>{userQ.data?.email}</dd>
            <dt className="text-muted">Username</dt>
            <dd>{userQ.data?.username}</dd>
            <dt className="text-muted">Role</dt>
            <dd className="font-mono">{userQ.data?.role}</dd>
            <dt className="text-muted">2FA</dt>
            <dd>
              {userQ.data?.totp_enabled ? (
                "TOTP enabled"
              ) : (
                <span className="text-faint">off</span>
              )}
            </dd>
            <dt className="text-muted">Last login</dt>
            <dd className="text-muted">
              {userQ.data?.last_login_at
                ? new Date(userQ.data.last_login_at).toLocaleString()
                : "—"}
            </dd>
          </dl>
        )}
      </section>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Peers ({peers.length})</h2>
        </div>
        {peersQ.isLoading ? (
          <p className="text-muted">Loading…</p>
        ) : peers.length === 0 ? (
          <div className="panel">
            <p className="text-muted">
              No peers for this user yet. Click <strong>+ Add peer</strong>.
            </p>
          </div>
        ) : (
          <div className="data-table">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Location</th>
                  <th>Assigned IP</th>
                  <th title="Client routed networks — the [Peer] AllowedIPs the peer's exported .conf installs. NOT the server-side wg show value.">
                    Client routes
                  </th>
                  <th>Last handshake</th>
                  <th>RX / TX</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {peers.map((p) => {
                  const iface = ifaceByID.get(p.interface_id);
                  const recentMs =
                    p.last_handshake && !p.last_handshake.startsWith("0001-")
                      ? nowMs - new Date(p.last_handshake).getTime()
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
                      <td className="text-muted">
                        {iface?.name ?? (
                          <span className="text-faint font-mono">
                            {p.interface_id.slice(0, 8)}
                          </span>
                        )}
                      </td>
                      <td className="font-mono text-muted">{p.assigned_ip}</td>
                      <td className="text-muted">
                        <NetworksCell items={p.client_allowed_ips ?? []} />
                      </td>
                      <td className="text-muted">
                        {p.last_handshake &&
                        !p.last_handshake.startsWith("0001-")
                          ? new Date(p.last_handshake).toLocaleString()
                          : "—"}
                      </td>
                      <td className="text-muted font-mono text-xs">
                        {formatBytes(p.rx_bytes)} / {formatBytes(p.tx_bytes)}
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
                            onClick={() => setEditPeer(toEditable(p))}
                            className="btn-ghost"
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              if (
                                !confirm(
                                  `Delete peer "${p.name}"? This revokes the VPN credentials.`,
                                )
                              )
                                return;
                              deleteMut.mutate(p.id);
                            }}
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
      </section>

      {configPeer && (
        <PeerConfigModal
          key={`${configPeer.id}:${peerVersions[configPeer.id] ?? 0}`}
          peerId={configPeer.id}
          peerName={configPeer.name}
          onEdit={() => {
            const full = peers.find((p) => p.id === configPeer.id);
            if (full) {
              setConfigPeer(null);
              setEditPeer(toEditable(full));
            }
          }}
          onClose={() => setConfigPeer(null)}
        />
      )}
      {editPeer && (
        <PeerEditModal
          peer={editPeer}
          onClose={() => setEditPeer(null)}
          onSaved={() => {
            bumpVersion(editPeer.id);
            setEditPeer(null);
            qc.invalidateQueries({ queryKey: ["peers-by-owner", userID] });
          }}
        />
      )}
      {showCreate && defaultIfaceID && (
        <PeerCreateModal
          interfaceID={defaultIfaceID}
          ownerUserID={userID}
          ownerLocked
          onClose={() => setShowCreate(false)}
          onCreated={(peer) => {
            setShowCreate(false);
            setConfigPeer({ id: peer.id, name: peer.name });
            qc.invalidateQueries({ queryKey: ["peers-by-owner", userID] });
          }}
        />
      )}
    </div>
  );
}

// NetworksCell duplicates the helper from PeersPage so the user
// detail table renders the routed-CIDR summary identically. Kept
// local to avoid pulling a tiny component into a separate file.
function NetworksCell({ items }: { items: string[] }) {
  if (items.length === 0) {
    return <span className="text-faint">(default)</span>;
  }
  const head = items.slice(0, 2);
  const rest = items.length - head.length;
  return (
    <span title={items.join(", ")} className="font-mono text-xs">
      {head.join(", ")}
      {rest > 0 && <span className="text-faint">{` +${rest}`}</span>}
    </span>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
