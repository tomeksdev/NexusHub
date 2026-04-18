import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'

interface AuditEntry {
  id: number
  occurred_at: string
  actor_user_id?: string | null
  actor_ip?: string | null
  actor_ua?: string | null
  action: string
  target_type: string
  target_id?: string | null
  metadata?: Record<string, unknown>
  result: 'success' | 'failure' | 'denied'
  error_message?: string | null
}

const PAGE_SIZE = 50

interface Filters {
  action: string
  result: '' | 'success' | 'failure' | 'denied'
  since: string // yyyy-mm-ddThh:mm (local, from <input type="datetime-local">)
}

export function AuditPage() {
  const [filters, setFilters] = useState<Filters>({ action: '', result: '', since: '' })
  const [offset, setOffset] = useState(0)

  const qs = useMemo(() => {
    const p = new URLSearchParams()
    p.set('limit', String(PAGE_SIZE))
    p.set('offset', String(offset))
    if (filters.action) p.set('action', filters.action)
    if (filters.result) p.set('result', filters.result)
    if (filters.since) {
      // datetime-local produces a naive local string; convert to UTC ISO for the server.
      const iso = new Date(filters.since).toISOString()
      p.set('since', iso)
    }
    return p.toString()
  }, [filters, offset])

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['audit', qs],
    queryFn: () => api<PageEnvelope<AuditEntry>>(`/api/v1/audit-log?${qs}`),
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const hasNext = offset + PAGE_SIZE < total
  const hasPrev = offset > 0

  function onFilterChange<K extends keyof Filters>(key: K, value: Filters[K]) {
    setFilters((f) => ({ ...f, [key]: value }))
    // Filter changes reset pagination — otherwise a client filtered to 3
    // items on page 5 sees an empty table and thinks the app is broken.
    setOffset(0)
  }

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Audit log</h1>
        <span className="text-sm text-slate-500">{total} entries</span>
      </header>

      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-slate-400">Action</label>
          <input
            value={filters.action}
            onChange={(e) => onFilterChange('action', e.target.value)}
            placeholder="e.g. auth.login"
            className="rounded-md bg-slate-800 border border-slate-700 px-2 py-1 text-sm w-48"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-slate-400">Result</label>
          <select
            value={filters.result}
            onChange={(e) => onFilterChange('result', e.target.value as Filters['result'])}
            className="rounded-md bg-slate-800 border border-slate-700 px-2 py-1 text-sm"
          >
            <option value="">any</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
            <option value="denied">denied</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-slate-400">Since</label>
          <input
            type="datetime-local"
            value={filters.since}
            onChange={(e) => onFilterChange('since', e.target.value)}
            className="rounded-md bg-slate-800 border border-slate-700 px-2 py-1 text-sm"
          />
        </div>
      </div>

      {isLoading ? (
        <p className="text-slate-400 text-sm">Loading…</p>
      ) : isError ? (
        <p className="text-rose-400 text-sm">Failed to load: {(error as Error).message}</p>
      ) : items.length === 0 ? (
        <p className="text-slate-400 text-sm">No entries match the current filters.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Target</th>
                <th className="px-4 py-2 font-medium">Actor</th>
                <th className="px-4 py-2 font-medium">Result</th>
                <th className="px-4 py-2 font-medium">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {items.map((e) => (
                <tr key={e.id} className="hover:bg-slate-900/50">
                  <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                    {new Date(e.occurred_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-200">{e.action}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-400">
                    {e.target_type}
                    {e.target_id ? <span className="text-slate-500">:{shortID(e.target_id)}</span> : null}
                  </td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">
                    {e.actor_ip ?? (e.actor_user_id ? shortID(e.actor_user_id) : '—')}
                  </td>
                  <td className="px-4 py-2">
                    <span className={resultBadge(e.result)}>{e.result}</span>
                  </td>
                  <td className="px-4 py-2 text-slate-500 text-xs truncate max-w-[30ch]">
                    {e.error_message ?? ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex items-center justify-between text-sm">
        <span className="text-slate-500">
          {total === 0
            ? ''
            : `Showing ${offset + 1}–${Math.min(offset + items.length, total)} of ${total}`}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
            disabled={!hasPrev}
            className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800"
          >
            Previous
          </button>
          <button
            onClick={() => setOffset((o) => o + PAGE_SIZE)}
            disabled={!hasNext}
            className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}

function resultBadge(r: string): string {
  const base = 'inline-flex px-2 py-0.5 rounded-full text-xs '
  if (r === 'success') return base + 'bg-emerald-900/40 text-emerald-400'
  if (r === 'failure') return base + 'bg-rose-900/40 text-rose-400'
  return base + 'bg-amber-900/40 text-amber-400'
}

function shortID(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
}
