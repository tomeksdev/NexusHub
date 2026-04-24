// Auth context. Holds the "am I logged in" bit and role so downstream
// components can branch on it without threading props. The token lifecycle
// itself lives in api.ts — this file is just React glue plus the tiny
// bit of localStorage we use to persist the user's profile across reloads.
//
// Why persist role + email alongside the refresh token: on reload we
// already trust the refresh token (same storage), and the role isn't
// secret — it's embedded in the access JWT the server already hands us.
// Storing a hint lets us render the authenticated shell immediately
// instead of flashing the login screen while /refresh round-trips.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { clearTokens, getRefreshToken, login as apiLogin, logout as apiLogout, onAuthLost } from './api'

export type Role = 'super_admin' | 'admin' | 'user'

export interface AuthState {
  isAuthenticated: boolean
  role: Role | null
  email: string | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => Promise<void>
}

const PROFILE_KEY = 'nexushub.profile'

interface StoredProfile {
  role: Role
  email: string
}

function loadProfile(): StoredProfile | null {
  if (!getRefreshToken()) return null
  const raw = localStorage.getItem(PROFILE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as StoredProfile
  } catch {
    return null
  }
}

function saveProfile(p: StoredProfile) {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(p))
}

function clearProfile() {
  localStorage.removeItem(PROFILE_KEY)
}

const AuthCtx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const initial = loadProfile()
  const [role, setRole] = useState<Role | null>(initial?.role ?? null)
  const [email, setEmail] = useState<string | null>(initial?.email ?? null)
  // No async bootstrap needed — we trust the stored profile until the
  // first API call fails with 401, at which point api.ts clears the
  // refresh token and our onAuthLost handler resets role/email.
  const [loading] = useState(false)

  useEffect(() => {
    onAuthLost(() => {
      setRole(null)
      setEmail(null)
      clearProfile()
    })
  }, [])

  const signIn = useCallback(async (e: string, password: string) => {
    const res = await apiLogin(e, password)
    const r = res.role as Role
    setRole(r)
    setEmail(e)
    saveProfile({ role: r, email: e })
  }, [])

  const signOut = useCallback(async () => {
    await apiLogout()
    clearTokens()
    clearProfile()
    setRole(null)
    setEmail(null)
  }, [])

  const value = useMemo<AuthState>(
    () => ({
      isAuthenticated: role !== null,
      role,
      email,
      loading,
      signIn,
      signOut,
    }),
    [role, email, loading, signIn, signOut],
  )

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

// Co-located with AuthProvider intentionally — the hook reads the
// context created here, and splitting the file just to appease the
// fast-refresh plugin would churn every call site.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
