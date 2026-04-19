import { HttpResponse, http } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { server } from '../test/msw'
import {
  ApiError,
  api,
  clearTokens,
  getRefreshToken,
  hasSession,
  login,
  logout,
  setTokens,
} from './api'

// The api module holds accessToken + expiry in module-level state. Tests
// must reset that state themselves because no two tests should share a
// session. clearTokens() wipes both the in-memory access token and the
// localStorage refresh token.
beforeEach(() => clearTokens())
afterEach(() => clearTokens())

function farFuture(): string {
  return new Date(Date.now() + 10 * 60_000).toISOString()
}

describe('setTokens / hasSession', () => {
  it('reports a session once tokens are set', () => {
    expect(hasSession()).toBe(false)
    setTokens('at', farFuture(), 'rt')
    expect(hasSession()).toBe(true)
    expect(getRefreshToken()).toBe('rt')
  })

  it('lets the refresh token persist separately from the access token', () => {
    setTokens('at', farFuture(), 'rt')
    // Simulate page reload: in-memory access token is gone but the refresh
    // token is still in localStorage. hasSession() must still be true.
    clearTokens()
    expect(hasSession()).toBe(false)
    localStorage.setItem('nexushub.refresh', 'rt')
    expect(hasSession()).toBe(true)
  })
})

describe('api() auth behaviour', () => {
  it('attaches the Bearer header when an access token is loaded', async () => {
    setTokens('access-1', farFuture(), 'rt')
    let seenAuth = ''
    server.use(
      http.get('/api/v1/ping', ({ request }) => {
        seenAuth = request.headers.get('authorization') ?? ''
        return HttpResponse.json({ ok: true })
      }),
    )
    const out = await api<{ ok: boolean }>('/api/v1/ping')
    expect(out).toEqual({ ok: true })
    expect(seenAuth).toBe('Bearer access-1')
  })

  it('refreshes proactively when the access token is near expiry', async () => {
    // accessExpires five seconds in the future → inside the 30s pre-refresh
    // window, so api() should swap for a new token before the real call.
    setTokens('stale', new Date(Date.now() + 5_000).toISOString(), 'rt-1')
    const seenAuths: string[] = []
    server.use(
      http.post('/api/v1/auth/refresh', async ({ request }) => {
        const body = (await request.json()) as { refresh_token: string }
        expect(body.refresh_token).toBe('rt-1')
        return HttpResponse.json({
          access_token: 'fresh',
          access_expires_at: farFuture(),
          refresh_token: 'rt-2',
        })
      }),
      http.get('/api/v1/ping', ({ request }) => {
        seenAuths.push(request.headers.get('authorization') ?? '')
        return HttpResponse.json({ ok: true })
      }),
    )
    await api('/api/v1/ping')
    expect(seenAuths).toEqual(['Bearer fresh'])
    expect(getRefreshToken()).toBe('rt-2')
  })

  it('retries once after a 401 by refreshing', async () => {
    setTokens('old', farFuture(), 'rt-1')
    let pingHits = 0
    server.use(
      http.get('/api/v1/ping', ({ request }) => {
        pingHits++
        const auth = request.headers.get('authorization')
        if (auth === 'Bearer old') {
          return HttpResponse.json(
            { error: 'expired', code: 'UNAUTHORIZED' },
            { status: 401 },
          )
        }
        return HttpResponse.json({ ok: true })
      }),
      http.post('/api/v1/auth/refresh', () =>
        HttpResponse.json({
          access_token: 'new',
          access_expires_at: farFuture(),
          refresh_token: 'rt-2',
        }),
      ),
    )
    await api('/api/v1/ping')
    expect(pingHits).toBe(2)
    expect(getRefreshToken()).toBe('rt-2')
  })

  it('clears tokens + throws ApiError when refresh itself fails', async () => {
    setTokens('old', farFuture(), 'rt-1')
    server.use(
      http.get('/api/v1/ping', () =>
        HttpResponse.json({ error: 'expired', code: 'UNAUTHORIZED' }, { status: 401 }),
      ),
      http.post('/api/v1/auth/refresh', () =>
        HttpResponse.json({ error: 'bad', code: 'UNAUTHORIZED' }, { status: 401 }),
      ),
    )
    await expect(api('/api/v1/ping')).rejects.toBeInstanceOf(ApiError)
    expect(hasSession()).toBe(false)
  })

  it('returns undefined on 204', async () => {
    setTokens('at', farFuture(), 'rt')
    server.use(http.delete('/api/v1/x', () => new HttpResponse(null, { status: 204 })))
    const out = await api('/api/v1/x', { method: 'DELETE' })
    expect(out).toBeUndefined()
  })

  it('surfaces error code + status on non-ok JSON responses', async () => {
    setTokens('at', farFuture(), 'rt')
    server.use(
      http.post('/api/v1/peers', () =>
        HttpResponse.json(
          { error: 'ip already assigned', code: 'CONFLICT' },
          { status: 409 },
        ),
      ),
    )
    let err: unknown
    try {
      await api('/api/v1/peers', { method: 'POST', body: '{}' })
    } catch (e) {
      err = e
    }
    expect(err).toBeInstanceOf(ApiError)
    const e = err as ApiError
    expect(e.status).toBe(409)
    expect(e.code).toBe('CONFLICT')
    expect(e.message).toBe('ip already assigned')
  })
})

describe('login / logout', () => {
  it('persists both tokens after login', async () => {
    server.use(
      http.post('/api/v1/auth/login', () =>
        HttpResponse.json({
          access_token: 'A',
          refresh_token: 'R',
          access_expires_at: farFuture(),
          role: 'admin',
        }),
      ),
    )
    const resp = await login('u@example.com', 'pw')
    expect(resp.role).toBe('admin')
    expect(getRefreshToken()).toBe('R')
    expect(hasSession()).toBe(true)
  })

  it('surfaces ApiError on bad credentials', async () => {
    server.use(
      http.post('/api/v1/auth/login', () =>
        HttpResponse.json(
          { error: 'bad creds', code: 'UNAUTHORIZED' },
          { status: 401 },
        ),
      ),
    )
    await expect(login('u@example.com', 'wrong')).rejects.toBeInstanceOf(ApiError)
  })

  it('best-effort logout clears local state even when the server fails', async () => {
    setTokens('at', farFuture(), 'rt')
    server.use(
      http.post('/api/v1/auth/logout', () => HttpResponse.error()),
    )
    await logout()
    expect(hasSession()).toBe(false)
    expect(getRefreshToken()).toBeNull()
  })
})
