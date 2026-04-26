import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { api, type PageEnvelope } from '../lib/api'
import { useNowEveryMinute } from '../lib/hooks'

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
  const { t } = useTranslation()
  const nowMs = useNowEveryMinute()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => api<PageEnvelope<User>>('/api/v1/users?limit=100'),
  })

  if (isLoading) return <div className="p-6 text-slate-400">{t('common.loading')}</div>
  if (isError)
    return (
      <div className="p-6 text-rose-400">
        {t('common.loadFailed', { message: (error as Error).message })}
      </div>
    )

  const items = data?.items ?? []

  return (
    <div className="p-6 space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{t('users.title')}</h1>
        <span className="text-sm text-slate-500">
          {t('common.total', { count: data?.total ?? 0 })}
        </span>
      </header>
      {items.length === 0 ? (
        <p className="text-slate-400 text-sm">{t('users.empty')}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-slate-400 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">{t('users.col.email')}</th>
                <th className="px-4 py-2 font-medium">{t('users.col.username')}</th>
                <th className="px-4 py-2 font-medium">{t('users.col.role')}</th>
                <th className="px-4 py-2 font-medium">{t('users.col.status')}</th>
                <th className="px-4 py-2 font-medium">{t('users.col.twoFA')}</th>
                <th className="px-4 py-2 font-medium">{t('users.col.lastLogin')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {items.map((u) => {
                const locked = !!u.locked_until && new Date(u.locked_until).getTime() > nowMs
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
                          {t('users.status.disabled')}
                        </span>
                      ) : locked ? (
                        <span className="inline-flex px-2 py-0.5 rounded-full bg-rose-900/40 text-rose-400 text-xs">
                          {t('users.status.locked')}
                        </span>
                      ) : (
                        <span className="inline-flex px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-xs">
                          {t('users.status.active')}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-300">
                      {u.totp_enabled ? (
                        'TOTP'
                      ) : (
                        <span className="text-slate-500">{t('users.twoFA.off')}</span>
                      )}
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
