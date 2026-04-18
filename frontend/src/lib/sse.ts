// sseStream opens a Server-Sent Events stream using fetch() so we can pass
// an Authorization header — the browser's built-in EventSource only supports
// cookies. The implementation is intentionally minimal: it parses the subset
// of the SSE grammar the backend actually emits (event/data lines, blank-line
// dispatch) and does not attempt automatic reconnection. Callers that want
// reconnect semantics should call sseStream again when onClose fires.

import { getAccessTokenForStream } from './api'

export interface SSEHandlers {
  onEvent: (event: string, data: string) => void
  onClose?: () => void
  onError?: (err: unknown) => void
  signal?: AbortSignal
}

export async function sseStream(path: string, h: SSEHandlers): Promise<void> {
  const token = await getAccessTokenForStream()
  let resp: Response
  try {
    resp = await fetch(path, {
      headers: {
        Accept: 'text/event-stream',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      signal: h.signal,
    })
  } catch (err) {
    h.onError?.(err)
    h.onClose?.()
    return
  }
  if (!resp.ok || !resp.body) {
    h.onError?.(new Error(`sse: ${resp.status}`))
    h.onClose?.()
    return
  }

  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let event = 'message'
  let data = ''

  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })

      // SSE frames end in a blank line. We split on '\n', keep the last
      // partial line in the buffer, and dispatch whenever an empty line
      // terminates a frame.
      let nl: number
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl).replace(/\r$/, '')
        buffer = buffer.slice(nl + 1)
        if (line === '') {
          if (data) h.onEvent(event, data)
          event = 'message'
          data = ''
          continue
        }
        if (line.startsWith(':')) continue // comment
        const colon = line.indexOf(':')
        const field = colon < 0 ? line : line.slice(0, colon)
        const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
        if (field === 'event') event = value
        else if (field === 'data') data = data ? data + '\n' + value : value
      }
    }
  } catch (err) {
    h.onError?.(err)
  } finally {
    h.onClose?.()
  }
}
