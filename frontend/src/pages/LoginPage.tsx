import { useState, useRef, useEffect } from 'react'
import type { FormEvent } from 'react'

import { ApiError } from '../lib/api'
import { useAuth } from '../lib/auth'

export function LoginPage() {
  const { signIn } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  // needsTOTP drives the two-step UX: the first submit posts email
  // +password; if the server answers TOTP_REQUIRED we surface the
  // code field, retain the entered credentials (in state only), and
  // let the user retry with the 6-digit code without re-typing.
  const [needsTOTP, setNeedsTOTP] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const totpRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (needsTOTP) totpRef.current?.focus()
  }, [needsTOTP])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr(null)
    setBusy(true)
    try {
      await signIn(email, password, needsTOTP ? totpCode : undefined)
    } catch (ex) {
      if (ex instanceof ApiError) {
        if (ex.code === 'TOTP_REQUIRED') {
          // Promote to the second step. Keep email/password in state
          // so the next submit includes them automatically.
          setNeedsTOTP(true)
          setErr(null)
        } else if (ex.code === 'TOTP_INVALID') {
          setErr('Invalid authenticator code.')
          setTotpCode('')
        } else if (ex.code === 'INVALID_CREDENTIALS') {
          setErr('Invalid email or password.')
          // If we were in the TOTP step, bail back to step one so
          // the user can correct whichever piece is actually wrong.
          setNeedsTOTP(false)
          setTotpCode('')
        } else {
          setErr(ex.message)
        }
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
        <p className="text-sm text-slate-400">
          {needsTOTP ? 'Enter the 6-digit code from your authenticator app.' : 'Sign in to continue.'}
        </p>

        {!needsTOTP && (
          <>
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
          </>
        )}

        {needsTOTP && (
          <div className="space-y-1">
            <label htmlFor="totp" className="text-sm text-slate-300">
              Authenticator code
            </label>
            <input
              id="totp"
              ref={totpRef}
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="\d{6}"
              maxLength={6}
              required
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
              className="w-full rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-lg tracking-[0.5em] text-center font-mono focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-1 focus:border-sky-500"
            />
            <button
              type="button"
              onClick={() => {
                setNeedsTOTP(false)
                setTotpCode('')
                setErr(null)
              }}
              className="text-xs text-slate-500 hover:text-slate-300"
            >
              ← Use a different account
            </button>
          </div>
        )}

        {err && <p className="text-sm text-rose-400">{err}</p>}

        <button
          type="submit"
          disabled={busy || (needsTOTP && totpCode.length !== 6)}
          className="w-full rounded-md bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-400 px-4 py-2 text-sm font-medium focus-visible:outline-2 focus-visible:outline-sky-400 focus-visible:outline-offset-2"
        >
          {busy ? 'Signing in…' : needsTOTP ? 'Verify' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
