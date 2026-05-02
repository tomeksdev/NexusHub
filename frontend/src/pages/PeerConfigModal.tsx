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
    // navigator.clipboard is only defined on secure contexts (https or
    // localhost). Bare-metal installs commonly run over plain http on a
    // LAN — fall back to the execCommand path so Copy still works there.
    try {
      if (
        typeof navigator !== "undefined" &&
        navigator.clipboard?.writeText &&
        window.isSecureContext
      ) {
        await navigator.clipboard.writeText(conf);
      } else {
        legacyCopy(conf);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  function legacyCopy(text: string) {
    const ta = document.createElement("textarea");
    ta.value = text;
    // Off-screen rather than display:none — selection requires the
    // element to be in the layout tree.
    ta.style.position = "fixed";
    ta.style.top = "-9999px";
    ta.setAttribute("readonly", "");
    document.body.appendChild(ta);
    try {
      ta.select();
      // execCommand is deprecated but still the only path that works in
      // a plain-http context. The dom-deprecations rule isn't worth a
      // ts-ignore over.
      document.execCommand("copy");
    } finally {
      document.body.removeChild(ta);
    }
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
        <div className="text-danger text-sm">Failed to load: {error}</div>
      ) : !conf || !qrUrl ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : (
        <div className="grid md:grid-cols-[1fr_auto] gap-5">
          <div className="min-w-0">
            <pre
              className="rounded-md p-3 text-xs font-mono overflow-auto max-h-80 whitespace-pre-wrap break-all"
              style={{
                background: "#111",
                border: "1px solid var(--color-line-strong)",
                color: "var(--color-text)",
              }}
            >
              {conf}
            </pre>
            <div className="flex gap-2 mt-3">
              <button onClick={copy} className="btn-ghost">
                {copied ? "Copied" : "Copy"}
              </button>
              <button onClick={download} className="btn-ghost">
                Download .conf
              </button>
              <button
                onClick={rotatePSK}
                disabled={rotating}
                className="btn-primary ml-auto"
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
            <p className="text-faint text-xs">
              Scan in the WireGuard mobile app
            </p>
          </div>
        </div>
      )}
    </Modal>
  );
}
