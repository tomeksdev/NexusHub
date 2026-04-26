import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'
import { RuleEditorModal } from './RuleEditorModal'

export interface Rule {
  id: string
  name: string
  description?: string
  action: 'allow' | 'deny' | 'rate_limit' | 'log'
  direction: 'ingress' | 'egress' | 'both'
  protocol: 'any' | 'tcp' | 'udp' | 'icmp'
  src_cidr?: string
  dst_cidr?: string
  src_port_from?: number
  src_port_to?: number
  dst_port_from?: number
  dst_port_to?: number
  rate_pps?: number
  rate_burst?: number
  priority: number
  is_active: boolean
  created_at: string
  updated_at: string
}

const actionBadge: Record<Rule['action'], string> = {
  allow: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  deny: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  rate_limit: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  log: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
}

function summarisePorts(from?: number, to?: number): string {
  if (from == null && to == null) return '*'
  if (from != null && to != null) return from === to ? `${from}` : `${from}-${to}`
  return `${from ?? to ?? '*'}`
}

export function RulesPage() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['rules'],
    queryFn: () =>
      api<PageEnvelope<Rule>>('/api/v1/rules?limit=200&sort=-priority'),
  })

  const toggleMut = useMutation({
    mutationFn: (r: Rule) =>
      api(`/api/v1/rules/${r.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: !r.is_active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api(`/api/v1/rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const onDelete = (r: Rule) => {
    if (!confirm(`Delete rule "${r.name}"? This cannot be undone.`)) return
    deleteMut.mutate(r.id)
  }

  if (isLoading) return <div className="p-6 text-slate-400">Loading rules…</div>
  if (isError)
    return <div className="p-6 text-rose-400">Failed to load: {(error as Error).message}</div>

  const items = data?.items ?? []

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-semibold">eBPF rules</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Rules apply in descending priority order. Kernel enforcement is
            a no-op until the eBPF loader is wired in production (Phase 5).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-500">{data?.total ?? 0} total</span>
          <button
            onClick={() => setCreating(true)}
            className="px-3 py-1.5 rounded-md text-sm bg-indigo-600 hover:bg-indigo-500"
          >
            New rule
          </button>
        </div>
      </header>

      {items.length === 0 ? (
        <p className="text-slate-400 text-sm">
          No rules yet. Click <strong>New rule</strong> to create the first.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Priority</th>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Direction</th>
                <th className="px-4 py-2 font-medium">Protocol</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Destination</th>
                <th className="px-4 py-2 font-medium">Active</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-t border-slate-800 hover:bg-slate-900/50">
                  <td className="px-4 py-2 text-slate-400">{r.priority}</td>
                  <td className="px-4 py-2">
                    <div className="font-medium">{r.name}</div>
                    {r.description && (
                      <div className="text-xs text-slate-500">{r.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={
                        'inline-block px-2 py-0.5 rounded border text-xs ' +
                        actionBadge[r.action]
                      }
                    >
                      {r.action}
                      {r.action === 'rate_limit' && r.rate_pps && (
                        <span className="ml-1 text-slate-400">{r.rate_pps}/s</span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-400">{r.direction}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {r.protocol}
                    {(r.protocol === 'tcp' || r.protocol === 'udp') && (
                      <span className="ml-1 text-slate-500 text-xs">
                        :{summarisePorts(r.src_port_from, r.src_port_to)}→
                        {summarisePorts(r.dst_port_from, r.dst_port_to)}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-400">
                    {r.src_cidr ?? <span className="text-slate-500">any</span>}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-400">
                    {r.dst_cidr ?? <span className="text-slate-500">any</span>}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => toggleMut.mutate(r)}
                      disabled={toggleMut.isPending}
                      className={
                        'px-2 py-0.5 rounded text-xs border ' +
                        (r.is_active
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-500 border-slate-700')
                      }
                    >
                      {r.is_active ? 'on' : 'off'}
                    </button>
                  </td>
                  <td className="px-4 py-2 text-right space-x-2 whitespace-nowrap">
                    <button
                      onClick={() => setEditing(r)}
                      className="text-slate-400 hover:text-slate-200 text-xs"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => onDelete(r)}
                      className="text-rose-400 hover:text-rose-300 text-xs"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && <RuleEditorModal rule={null} onClose={() => setCreating(false)} />}
      {editing && <RuleEditorModal rule={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}
