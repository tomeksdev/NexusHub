import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { LanguageSwitcher } from './components/LanguageSwitcher'
import { useAuth } from './lib/auth'
import { AuditPage } from './pages/AuditPage'
import { InterfacesPage } from './pages/InterfacesPage'
import { LoginPage } from './pages/LoginPage'
import { MetricsPage } from './pages/MetricsPage'
import { PeersPage } from './pages/PeersPage'
import { RulesPage } from './pages/RulesPage'
import { UsersPage } from './pages/UsersPage'

type Page = 'peers' | 'interfaces' | 'rules' | 'users' | 'audit' | 'metrics'

const NAV_ORDER: Page[] = ['peers', 'interfaces', 'rules', 'metrics', 'users', 'audit']

function App() {
  const { t } = useTranslation()
  const { isAuthenticated, email, signOut } = useAuth()
  const [page, setPage] = useState<Page>('peers')

  if (!isAuthenticated) return <LoginPage />

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100">
      {/* Skip link: visually hidden until keyboard-focused, jumps past the
          nav to the main region. Critical for keyboard and screen-reader
          users who would otherwise tab through the whole sidebar on
          every page view. */}
      <a
        href="#main-content"
        className="sr-only focus-visible:not-sr-only focus-visible:fixed focus-visible:top-2 focus-visible:left-2 focus-visible:z-50 focus-visible:px-3 focus-visible:py-2 focus-visible:rounded-md focus-visible:bg-indigo-600 focus-visible:text-white"
      >
        Skip to content
      </a>
      <aside className="w-56 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-800">
          <h1 className="font-semibold">{t('app.title')}</h1>
          <p className="text-xs text-slate-500 mt-0.5">{t('app.subtitle')}</p>
        </div>
        <nav aria-label="Primary" className="flex-1 px-2 py-3 space-y-0.5">
          {NAV_ORDER.map((id) => (
            <button
              key={id}
              onClick={() => setPage(id)}
              aria-current={page === id ? 'page' : undefined}
              className={
                'w-full text-left px-3 py-2 rounded-md text-sm transition focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2 ' +
                (page === id
                  ? 'bg-slate-800 text-slate-100'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200')
              }
            >
              {t(`nav.${id}`)}
            </button>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-slate-800 space-y-2">
          <LanguageSwitcher />
          <p className="text-xs text-slate-500 truncate" title={email ?? ''}>
            {email}
          </p>
          <button
            onClick={signOut}
            className="w-full text-left px-3 py-1.5 rounded-md text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          >
            {t('app.signOut')}
          </button>
        </div>
      </aside>

      <main id="main-content" tabIndex={-1} className="flex-1 overflow-y-auto">
        {page === 'peers' && <PeersPage />}
        {page === 'interfaces' && <InterfacesPage />}
        {page === 'rules' && <RulesPage />}
        {page === 'metrics' && <MetricsPage />}
        {page === 'users' && <UsersPage />}
        {page === 'audit' && <AuditPage />}
      </main>
    </div>
  )
}

export default App
