import { useQuery } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'

interface WGInterface {
  id: string
  name: string
  listen_port: number
  address: string
  dns: string[]
  mtu?: number | null
  endpoint?: string | null
  public_key: string
  is_active: boolean
  created_at: string
}

interface WGStatusDevice {
  name: string
  type: string
  listen_port: number
  peer_count: number
}

interface WGStatus {
  mode: string
  devices: WGStatusDevice[]
}

export function InterfacesPage() {
  const list = useQuery({
    queryKey: ['interfaces'],
    queryFn: () => api<PageEnvelope<WGInterface>>('/api/v1/interfaces?limit=100'),
  })
  // Status is a separate call because it joins live kernel state that may
  // differ from the DB rows. Showing both side-by-side surfaces drift —
  // "interface configured but device not up" is the most common bug
  // operators hit after a reboot.
  const status = useQuery({
    queryKey: ['wg-status'],
    queryFn: () => api<WGStatus>('/api/v1/wg/status'),
    refetchInterval: 10_000,
  })

  const statusByName = new Map<string, WGStatusDevice>()
  for (const d of status.data?.devices ?? []) statusByName.set(d.name, d)

  if (list.isLoading) return <div className="p-6 text-slate-400">Loading interfaces…</div>
  if (list.isError)
    return <div className="p-6 text-rose-400">Failed to load: {(list.error as Error).message}</div>

  const items = list.data?.items ?? []

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Interfaces</h1>
        {status.data && (
          <span className="text-sm text-slate-400">
            mode: <span className="font-mono text-slate-300">{status.data.mode}</span>
          </span>
        )}
      </header>
      {items.length === 0 ? (
        <p className="text-slate-400 text-sm">No interfaces configured.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Address</th>
                <th className="px-4 py-2 font-medium">Listen port</th>
                <th className="px-4 py-2 font-medium">Live</th>
                <th className="px-4 py-2 font-medium">Peers</th>
                <th className="px-4 py-2 font-medium">Public key</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {items.map((iface) => {
                const live = statusByName.get(iface.name)
                const up = !!live && live.peer_count >= 0
                return (
                  <tr key={iface.id} className="hover:bg-slate-900/50">
                    <td className="px-4 py-2 font-medium">{iface.name}</td>
                    <td className="px-4 py-2 font-mono text-slate-300">{iface.address}</td>
                    <td className="px-4 py-2 text-slate-300">{iface.listen_port}</td>
                    <td className="px-4 py-2">
                      <span
                        className={
                          'inline-flex px-2 py-0.5 rounded-full text-xs ' +
                          (up
                            ? 'bg-emerald-900/40 text-emerald-400'
                            : 'bg-slate-800 text-slate-400')
                        }
                      >
                        {up ? (live?.type || 'up') : 'down'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-slate-300">
                      {live && live.peer_count >= 0 ? live.peer_count : '—'}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-slate-500 truncate max-w-[22ch]">
                      {iface.public_key}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
