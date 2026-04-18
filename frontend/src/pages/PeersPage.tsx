import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'
import { sseStream } from '../lib/sse'
import { PeerConfigModal } from './PeerConfigModal'
import { PeerCreateModal } from './PeerCreateModal'

interface Peer {
  id: string
  interface_id: string
  name: string
  public_key: string
  assigned_ip: string
  status: string
  last_handshake?: string | null
  rx_bytes: number
  tx_bytes: number
  created_at: string
}

// Live state keyed by public key. We merge this over the DB-sourced peer
// list so the table reflects real handshakes/traffic without refetching.
interface LivePeer {
  last_handshake: string
  rx_bytes: number
  tx_bytes: number
}

export function PeersPage() {
  const qc = useQueryClient()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['peers'],
    queryFn: async () => {
      // The /peers list endpoint requires interface_id. For the scaffold
      // we fetch interfaces first and display peers for the first one;
      // a real multi-interface UI would render a dropdown here.
      const ifaces = await api<PageEnvelope<{ id: string; interface_id?: string; name: string }>>(
        '/api/v1/interfaces?limit=1',
      )
      if (ifaces.items.length === 0) return { items: [], total: 0, ifaceID: null, ifaceName: null }
      const iface = ifaces.items[0]
      const peers = await api<PageEnvelope<Peer>>(
        `/api/v1/peers?interface_id=${iface.id}&limit=100`,
      )
      return { items: peers.items, total: peers.total, ifaceID: iface.id, ifaceName: iface.name }
    },
  })

  const [live, setLive] = useState<Record<string, LivePeer>>({})
  const [configPeer, setConfigPeer] = useState<{ id: string; name: string } | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const deleteMut = useMutation({
    mutationFn: (id: string) => api(`/api/v1/peers/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['peers'] }),
  })

  function onDelete(p: Peer) {
    if (!confirm(`Delete peer "${p.name}"? This revokes the VPN credentials.`)) return
    deleteMut.mutate(p.id)
  }

  // Open the SSE stream once. The stream multiplexes every interface's
  // peers, so we don't need to re-open it when the user switches views.
  useEffect(() => {
    const ctrl = new AbortController()
    sseStream('/api/v1/peers/events', {
      signal: ctrl.signal,
      onEvent: (event, raw) => {
        if (event === 'ping') return
        try {
          const payload = JSON.parse(raw) as
            | {
                interface: string
                public_key: string
                last_handshake: string
                rx_bytes: number
                tx_bytes: number
              }
            | Array<{
                interface: string
                public_key: string
                last_handshake: string
                rx_bytes: number
                tx_bytes: number
              }>
          const list = Array.isArray(payload) ? payload : [payload]
          setLive((prev) => {
            const next = { ...prev }
            for (const p of list) {
              next[p.public_key] = {
                last_handshake: p.last_handshake,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
              }
            }
            return next
          })
        } catch {
          // Malformed frame — ignore rather than tear down the stream.
        }
      },
    })
    return () => ctrl.abort()
  }, [])

  if (isLoading) return <div className="p-6 text-slate-400">Loading peers…</div>
  if (isError) return <div className="p-6 text-rose-400">Failed to load: {(error as Error).message}</div>

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Peers</h1>
        <div className="flex items-center gap-3">
          {data?.ifaceName && (
            <span className="text-sm text-slate-400">interface: {data.ifaceName}</span>
          )}
          {data?.ifaceID && (
            <button
              onClick={() => setShowCreate(true)}
              className="px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 text-sm font-medium"
            >
              + New peer
            </button>
          )}
        </div>
      </header>
      {data?.items.length === 0 ? (
        <p className="text-slate-400 text-sm">No peers yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Assigned IP</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Last handshake</th>
                <th className="px-4 py-2 font-medium">RX / TX</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {data?.items.map((p) => {
                const l = live[p.public_key]
                const handshake = l?.last_handshake ?? p.last_handshake
                const rx = l?.rx_bytes ?? p.rx_bytes
                const tx = l?.tx_bytes ?? p.tx_bytes
                const recentMs = handshake
                  ? Date.now() - new Date(handshake).getTime()
                  : Number.POSITIVE_INFINITY
                const isLive = recentMs < 3 * 60_000
                return (
                  <tr key={p.id} className="hover:bg-slate-900/50">
                    <td className="px-4 py-2 font-medium">
                      <span className="inline-flex items-center gap-2">
                        <span
                          className={
                            'inline-block w-1.5 h-1.5 rounded-full ' +
                            (isLive ? 'bg-emerald-400' : 'bg-slate-600')
                          }
                          aria-hidden
                        />
                        {p.name}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-slate-300">{p.assigned_ip}</td>
                    <td className="px-4 py-2">
                      <span className={statusClass(p.status)}>{p.status}</span>
                    </td>
                    <td className="px-4 py-2 text-slate-400">
                      {handshake && !isZeroTime(handshake)
                        ? new Date(handshake).toLocaleString()
                        : '—'}
                    </td>
                    <td className="px-4 py-2 text-slate-400 font-mono text-xs">
                      {formatBytes(rx)} / {formatBytes(tx)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <div className="inline-flex gap-1">
                        <button
                          onClick={() => setConfigPeer({ id: p.id, name: p.name })}
                          className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-xs"
                        >
                          Config
                        </button>
                        <button
                          onClick={() => onDelete(p)}
                          disabled={deleteMut.isPending}
                          className="px-2.5 py-1 rounded-md text-rose-300 hover:bg-rose-900/30 disabled:opacity-50 text-xs"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                )
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
            // Straight into the config modal — that's where the user gets
            // the QR/.conf they just came here to generate.
            setShowCreate(false)
            setConfigPeer({ id: peer.id, name: peer.name })
          }}
        />
      )}
    </div>
  )
}

function statusClass(s: string): string {
  switch (s) {
    case 'active':
      return 'inline-flex px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-xs'
    case 'expired':
      return 'inline-flex px-2 py-0.5 rounded-full bg-amber-900/40 text-amber-400 text-xs'
    default:
      return 'inline-flex px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-xs'
  }
}

// The backend emits Go's zero time (0001-01-01T00:00:00Z) for peers that
// never completed a handshake. Render those as '—' instead of "1/1/1" or
// similar browser-locale nonsense.
function isZeroTime(s: string): boolean {
  return s.startsWith('0001-')
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}
