import { useState } from 'react'
import type { FormEvent } from 'react'

import { ApiError } from '../lib/api'
import { useAuth } from '../lib/auth'

export function LoginPage() {
  const { signIn } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr(null)
    setBusy(true)
    try {
      await signIn(email, password)
    } catch (ex) {
      if (ex instanceof ApiError) {
        setErr(ex.code === 'INVALID_CREDENTIALS' ? 'Invalid email or password.' : ex.message)
      } else {
        setErr('Sign-in failed.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm rounded-xl bg-slate-900 border border-slate-800 p-8 space-y-4 shadow-2xl"
      >
        <h1 className="text-2xl font-semibold">NexusHub</h1>
        <p className="text-sm text-slate-400">Sign in to continue.</p>
        <div className="space-y-1">
          <label htmlFor="email" className="text-sm text-slate-300">
            Email
          </label>
          <input
            id="email"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-1 focus:border-sky-500"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="password" className="text-sm text-slate-300">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-1 focus:border-sky-500"
          />
        </div>
        {err && <p className="text-sm text-rose-400">{err}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-400 px-4 py-2 text-sm font-medium"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
