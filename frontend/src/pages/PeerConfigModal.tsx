import { useEffect, useState } from 'react'

import { apiBlob, apiText } from '../lib/api'

interface Props {
  peerId: string
  peerName: string
  onClose: () => void
}

export function PeerConfigModal({ peerId, peerName, onClose }: Props) {
  const [conf, setConf] = useState<string | null>(null)
  const [qrUrl, setQrUrl] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let objUrl: string | null = null
    let cancelled = false

    Promise.all([
      apiText(`/api/v1/peers/${peerId}/config`),
      apiBlob(`/api/v1/peers/${peerId}/config.png`),
    ])
      .then(([text, blob]) => {
        if (cancelled) return
        setConf(text)
        objUrl = URL.createObjectURL(blob)
        setQrUrl(objUrl)
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      })

    return () => {
      cancelled = true
      // Revoke on unmount so the blob can be GC'd. Chrome keeps the
      // underlying Blob alive as long as any object URL points at it.
      if (objUrl) URL.revokeObjectURL(objUrl)
    }
  }, [peerId])

  async function copy() {
    if (!conf) return
    await navigator.clipboard.writeText(conf)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  function download() {
    if (!conf) return
    const blob = new Blob([conf], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${peerName || 'peer'}.conf`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl rounded-xl bg-slate-900 border border-slate-800 shadow-xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold">Peer config</h2>
            <p className="text-xs text-slate-500">{peerName}</p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-sm px-2 py-1"
            aria-label="Close"
          >
            ✕
          </button>
        </header>

        {error ? (
          <div className="p-5 text-rose-400 text-sm">Failed to load: {error}</div>
        ) : !conf || !qrUrl ? (
          <div className="p-5 text-slate-400 text-sm">Loading…</div>
        ) : (
          <div className="grid md:grid-cols-[1fr_auto] gap-5 p-5">
            <div className="min-w-0">
              <pre className="bg-slate-950 border border-slate-800 rounded-md p-3 text-xs font-mono text-slate-300 overflow-auto max-h-80 whitespace-pre-wrap break-all">
                {conf}
              </pre>
              <div className="flex gap-2 mt-3">
                <button
                  onClick={copy}
                  className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-sm"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
                <button
                  onClick={download}
                  className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-sm"
                >
                  Download .conf
                </button>
              </div>
            </div>
            <div className="flex flex-col items-center gap-2">
              <img
                src={qrUrl}
                alt="WireGuard config QR"
                className="w-56 h-56 rounded-md bg-white p-2"
              />
              <p className="text-xs text-slate-500">Scan in the WireGuard mobile app</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
