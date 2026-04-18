import { useQuery } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'

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

export function PeersPage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['peers'],
    queryFn: async () => {
      // The /peers list endpoint requires interface_id. For the scaffold
      // we fetch interfaces first and display peers for the first one;
      // a real multi-interface UI would render a dropdown here.
      const ifaces = await api<PageEnvelope<{ id: string; name: string }>>(
        '/api/v1/interfaces?limit=1',
      )
      if (ifaces.items.length === 0) return { items: [], total: 0, ifaceName: null }
      const iface = ifaces.items[0]
      const peers = await api<PageEnvelope<Peer>>(
        `/api/v1/peers?interface_id=${iface.id}&limit=100`,
      )
      return { items: peers.items, total: peers.total, ifaceName: iface.name }
    },
  })

  if (isLoading) return <div className="p-6 text-slate-400">Loading peers…</div>
  if (isError) return <div className="p-6 text-rose-400">Failed to load: {(error as Error).message}</div>

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Peers</h1>
        {data?.ifaceName && (
          <span className="text-sm text-slate-400">interface: {data.ifaceName}</span>
        )}
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
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {data?.items.map((p) => (
                <tr key={p.id} className="hover:bg-slate-900/50">
                  <td className="px-4 py-2 font-medium">{p.name}</td>
                  <td className="px-4 py-2 font-mono text-slate-300">{p.assigned_ip}</td>
                  <td className="px-4 py-2">
                    <span className={statusClass(p.status)}>{p.status}</span>
                  </td>
                  <td className="px-4 py-2 text-slate-400">
                    {p.last_handshake ? new Date(p.last_handshake).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">
                    {formatBytes(p.rx_bytes)} / {formatBytes(p.tx_bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}
