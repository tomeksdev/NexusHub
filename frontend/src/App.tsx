import { useState } from 'react'

import { useAuth } from './lib/auth'
import { LoginPage } from './pages/LoginPage'
import { PeersPage } from './pages/PeersPage'

type Page = 'peers' | 'interfaces' | 'users' | 'audit'

const NAV: { id: Page; label: string }[] = [
  { id: 'peers', label: 'Peers' },
  { id: 'interfaces', label: 'Interfaces' },
  { id: 'users', label: 'Users' },
  { id: 'audit', label: 'Audit log' },
]

function App() {
  const { isAuthenticated, email, signOut } = useAuth()
  const [page, setPage] = useState<Page>('peers')

  if (!isAuthenticated) return <LoginPage />

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100">
      <aside className="w-56 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-800">
          <h1 className="font-semibold">NexusHub</h1>
          <p className="text-xs text-slate-500 mt-0.5">WireGuard manager</p>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => setPage(n.id)}
              className={
                'w-full text-left px-3 py-2 rounded-md text-sm transition ' +
                (page === n.id
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200')
              }
            >
              {n.label}
            </button>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-slate-800 space-y-2">
          <p className="text-xs text-slate-500 truncate" title={email ?? ''}>
            {email}
          </p>
          <button
            onClick={signOut}
            className="w-full text-left px-3 py-1.5 rounded-md text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        {page === 'peers' && <PeersPage />}
        {page === 'interfaces' && <Placeholder title="Interfaces" />}
        {page === 'users' && <Placeholder title="Users" />}
        {page === 'audit' && <Placeholder title="Audit log" />}
      </main>
    </div>
  )
}

function Placeholder({ title }: { title: string }) {
  return (
    <div className="p-6">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-sm text-slate-400 mt-2">Not yet implemented.</p>
    </div>
  )
}

export default App
