import { useEffect, useState } from "react";

import { Modal } from "../components/Modal";
import { api, apiBlob, apiText } from "../lib/api";

interface Props {
  peerId: string;
  peerName: string;
  onClose: () => void;
}

export function PeerConfigModal({ peerId, peerName, onClose }: Props) {
  const [conf, setConf] = useState<string | null>(null);
  const [qrUrl, setQrUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [reloadNonce, setReloadNonce] = useState(0);

  useEffect(() => {
    let objUrl: string | null = null;
    let cancelled = false;

    Promise.all([
      apiText(`/api/v1/peers/${peerId}/config`),
      apiBlob(`/api/v1/peers/${peerId}/config.png`),
    ])
      .then(([text, blob]) => {
        if (cancelled) return;
        setConf(text);
        objUrl = URL.createObjectURL(blob);
        setQrUrl(objUrl);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });

    return () => {
      cancelled = true;
      // Revoke on unmount so the blob can be GC'd. Chrome keeps the
      // underlying Blob alive as long as any object URL points at it.
      if (objUrl) URL.revokeObjectURL(objUrl);
    };
  }, [peerId, reloadNonce]);

  async function rotatePSK() {
    if (
      !confirm("Rotate the pre-shared key? The peer will need the new config.")
    )
      return;
    setRotating(true);
    try {
      await api(`/api/v1/peers/${peerId}/rotate-psk`, { method: "POST" });
      // Clear the rendered config so the old QR isn't briefly visible
      // while the new fetch is in flight.
      setConf(null);
      setQrUrl(null);
      setReloadNonce((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRotating(false);
    }
  }

  async function copy() {
    if (!conf) return;
    await navigator.clipboard.writeText(conf);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function download() {
    if (!conf) return;
    const blob = new Blob([conf], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${peerName || "peer"}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Modal
      title="Peer config"
      description={peerName}
      onClose={onClose}
      maxWidthClass="max-w-3xl"
    >
      {error ? (
        <div className="text-rose-400 text-sm">Failed to load: {error}</div>
      ) : !conf || !qrUrl ? (
        <div className="text-slate-400 text-sm">Loading…</div>
      ) : (
        <div className="grid md:grid-cols-[1fr_auto] gap-5">
          <div className="min-w-0">
            <pre className="bg-slate-950 border border-slate-800 rounded-md p-3 text-xs font-mono text-slate-300 overflow-auto max-h-80 whitespace-pre-wrap break-all">
              {conf}
            </pre>
            <div className="flex gap-2 mt-3">
              <button
                onClick={copy}
                className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-sm focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2"
              >
                {copied ? "Copied" : "Copy"}
              </button>
              <button
                onClick={download}
                className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-sm focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2"
              >
                Download .conf
              </button>
              <button
                onClick={rotatePSK}
                disabled={rotating}
                className="px-3 py-1.5 rounded-md bg-amber-900/40 text-amber-300 hover:bg-amber-900/60 disabled:opacity-50 text-sm ml-auto focus-visible:outline-2 focus-visible:outline-amber-400 focus-visible:outline-offset-2"
              >
                {rotating ? "Rotating…" : "Rotate PSK"}
              </button>
            </div>
          </div>
          <div className="flex flex-col items-center gap-2">
            <img
              src={qrUrl}
              alt="WireGuard config QR"
              className="w-56 h-56 rounded-md bg-white p-2"
            />
            <p className="text-xs text-slate-500">
              Scan in the WireGuard mobile app
            </p>
          </div>
        </div>
      )}
    </Modal>
  );
}
