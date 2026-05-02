import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { InterfaceCreateModal } from "./InterfaceCreateModal";
import { InterfaceEditModal } from "./InterfaceEditModal";

interface WGInterface {
  id: string;
  name: string;
  listen_port: number;
  address: string;
  dns: string[];
  mtu?: number | null;
  endpoint?: string | null;
  post_up?: string | null;
  post_down?: string | null;
  public_key: string;
  is_active: boolean;
  created_at: string;
}

interface WGStatusDevice {
  name: string;
  type: string;
  listen_port: number;
  peer_count: number;
}

interface WGStatus {
  mode: string;
  devices: WGStatusDevice[];
}

// Filename stayed InterfacesPage.tsx to keep the diff small. The export
// is mounted in App.tsx as `LocationsPage`; the operator-facing label
// is "Locations" everywhere. The DB table + REST endpoint stay
// `wg_interfaces` / `/api/v1/interfaces` — those are technical
// primitives.
export function InterfacesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState<WGInterface | null>(null);

  const list = useQuery({
    queryKey: ["interfaces"],
    queryFn: () =>
      api<PageEnvelope<WGInterface>>("/api/v1/interfaces?limit=100"),
  });
  const status = useQuery({
    queryKey: ["wg-status"],
    queryFn: () => api<WGStatus>("/api/v1/wg/status"),
    refetchInterval: 10_000,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      api(`/api/v1/interfaces/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["interfaces"] });
      qc.invalidateQueries({ queryKey: ["wg-status"] });
    },
  });

  const statusByName = new Map<string, WGStatusDevice>();
  for (const d of status.data?.devices ?? []) statusByName.set(d.name, d);

  if (list.isLoading)
    return <div className="p-6 text-muted">Loading locations…</div>;
  if (list.isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(list.error as Error).message}
      </div>
    );

  const items = list.data?.items ?? [];
  const onDelete = (iface: WGInterface) => {
    if (!confirm(`Delete location "${iface.name}"? Peers will be revoked.`))
      return;
    deleteMut.mutate(iface.id);
  };

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Locations</h1>
        <div className="topbar-actions">
          {status.data && (
            <span className="text-muted text-sm">
              mode:{" "}
              <span className="text-faint font-mono">{status.data.mode}</span>
            </span>
          )}
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn-primary"
          >
            + New location
          </button>
        </div>
      </div>

      <div className="stats-row">
        <div className="stat-card">
          <span className="stat-label">Total</span>
          <span className="stat-value">{items.length}</span>
        </div>
        <div className="stat-card success">
          <span className="stat-label">Up</span>
          <span className="stat-value">
            {items.filter((i) => statusByName.has(i.name)).length}
          </span>
        </div>
        <div className="stat-card warning">
          <span className="stat-label">Total peers</span>
          <span className="stat-value">
            {(status.data?.devices ?? []).reduce(
              (s, d) => s + (d.peer_count >= 0 ? d.peer_count : 0),
              0,
            )}
          </span>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="panel">
          <p className="text-muted">No locations configured yet.</p>
        </div>
      ) : (
        <div className="data-table">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>Listen port</th>
                <th>State</th>
                <th>Peers</th>
                <th>Public key</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((iface) => {
                const live = statusByName.get(iface.name);
                const up = !!live && live.peer_count >= 0;
                const portDrift =
                  !!live && live.listen_port !== iface.listen_port;
                return (
                  <tr key={iface.id}>
                    <td className="font-medium">{iface.name}</td>
                    <td className="font-mono text-muted">{iface.address}</td>
                    <td>
                      <span className="text-muted">{iface.listen_port}</span>
                      {portDrift && (
                        <span
                          title={`Live: ${live?.listen_port}`}
                          className="ml-2 status-badge warning"
                        >
                          <span className="dot" />
                          DRIFT
                        </span>
                      )}
                    </td>
                    <td>
                      {up ? (
                        <span className="status-badge ok">
                          <span className="dot" />
                          {live?.type || "UP"}
                        </span>
                      ) : (
                        <span className="status-badge muted">
                          <span className="dot" />
                          DOWN
                        </span>
                      )}
                    </td>
                    <td className="text-muted">
                      {live && live.peer_count >= 0 ? live.peer_count : "—"}
                    </td>
                    <td className="font-mono text-xs text-faint truncate max-w-[18ch]">
                      {iface.public_key}
                    </td>
                    <td className="text-right">
                      <div className="inline-flex gap-2">
                        <button
                          type="button"
                          onClick={() => setEditTarget(iface)}
                          className="btn-ghost"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => onDelete(iface)}
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

      {showCreate && (
        <InterfaceCreateModal
          onClose={() => setShowCreate(false)}
          onCreated={() => setShowCreate(false)}
        />
      )}
      {editTarget && (
        <InterfaceEditModal
          iface={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={() => {
            setEditTarget(null);
            qc.invalidateQueries({ queryKey: ["interfaces"] });
            qc.invalidateQueries({ queryKey: ["wg-status"] });
          }}
        />
      )}
    </div>
  );
}
