import { useQuery } from '@tanstack/react-query'

import { api, type PageEnvelope } from '../lib/api'

interface User {
  id: string
  email: string
  username: string
  role: 'super_admin' | 'admin' | 'user'
  is_active: boolean
  totp_enabled: boolean
  last_login_at?: string | null
  failed_logins: number
  locked_until?: string | null
  created_at: string
}

export function UsersPage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => api<PageEnvelope<User>>('/api/v1/users?limit=100'),
  })

  if (isLoading) return <div className="p-6 text-slate-400">Loading users…</div>
  if (isError)
    return <div className="p-6 text-rose-400">Failed to load: {(error as Error).message}</div>

  const items = data?.items ?? []

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Users</h1>
        <span className="text-sm text-slate-500">{data?.total ?? 0} total</span>
      </header>
      {items.length === 0 ? (
        <p className="text-slate-400 text-sm">No users yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Username</th>
                <th className="px-4 py-2 font-medium">Role</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">2FA</th>
                <th className="px-4 py-2 font-medium">Last login</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {items.map((u) => {
                const locked = !!u.locked_until && new Date(u.locked_until).getTime() > Date.now()
                return (
                  <tr key={u.id} className="hover:bg-slate-900/50">
                    <td className="px-4 py-2 font-medium">{u.email}</td>
                    <td className="px-4 py-2 text-slate-300">{u.username}</td>
                    <td className="px-4 py-2">
                      <span className={roleBadge(u.role)}>{u.role}</span>
                    </td>
                    <td className="px-4 py-2">
                      {!u.is_active ? (
                        <span className="inline-flex px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-xs">
                          disabled
                        </span>
                      ) : locked ? (
                        <span className="inline-flex px-2 py-0.5 rounded-full bg-rose-900/40 text-rose-400 text-xs">
                          locked
                        </span>
                      ) : (
                        <span className="inline-flex px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-xs">
                          active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-300">
                      {u.totp_enabled ? 'TOTP' : <span className="text-slate-500">off</span>}
                    </td>
                    <td className="px-4 py-2 text-slate-400">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—'}
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

function roleBadge(role: string): string {
  const base = 'inline-flex px-2 py-0.5 rounded-full text-xs '
  if (role === 'super_admin') return base + 'bg-purple-900/40 text-purple-300'
  if (role === 'admin') return base + 'bg-sky-900/40 text-sky-300'
  return base + 'bg-slate-800 text-slate-300'
}
