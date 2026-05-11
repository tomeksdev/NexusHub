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
    refetchOnWindowFocus: false,
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
                  <StatusBadge status={p.status} />
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
                    {p.last_handshake && !p.last_handshake.startsWith("0001-")
                      ? new Date(p.last_handshake).toLocaleString()
                      : "—"}
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

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case "enabled":
    case "active":
      return (
        <span className="status-badge ok">
          <span className="dot" />
          ENABLED
        </span>
      );
    case "disabled":
      return (
        <span className="status-badge muted">
          <span className="dot" />
          DISABLED
        </span>
      );
    default:
      return (
        <span className="status-badge muted">
          <span className="dot" />
          {status.toUpperCase()}
        </span>
      );
  }
}
