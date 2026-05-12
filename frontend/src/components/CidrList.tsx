import {
  forwardRef,
  useImperativeHandle,
  useState,
  type KeyboardEvent,
} from "react";

// Cheap client-side CIDR shape check. The deep validity (mask range,
// trailing zeros) is the server's job — this only catches typos
// before round-tripping a 400.
const CIDR_RE = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

// Imperative handle the parent uses to force-commit a pending draft
// at submit time. Without this, a Save click before the input loses
// focus or Enter/comma is pressed leaves the typed CIDR stuck as a
// draft — the parent's state never picks it up and the PATCH body
// silently excludes the new network. That was the round-7 "I added
// 10.10.0.0/24 but it didn't make it to the .conf" bug.
export interface CidrListHandle {
  flush(): string[];
}

interface Props {
  // Comma-separated parse on first render is the operator's typical
  // paste. After that we keep an array internally and emit it via
  // onChange so the parent doesn't have to remember the rules.
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  // hint displayed below the input — useful for the "client AllowedIPs
  // means destinations through the tunnel" callout in PeerEditModal.
  hint?: string;
  // Shown alongside chips when one of these "wide-open" CIDRs is
  // present. Doesn't block the value; just nudges the operator that
  // a full-tunnel route was a deliberate choice.
  warnFullTunnel?: boolean;
  // Hard-rejects 0.0.0.0/0 and ::/0 at the input gate, mirroring the
  // backend's server-side rule. Used by the server-side AllowedIPs
  // field where a full-tunnel filter defeats per-peer source validation.
  // The client-side field leaves this false so full-tunnel routing
  // remains a legitimate client choice (with the warnFullTunnel nudge).
  disallowFullTunnel?: boolean;
}

const FULL_TUNNEL_V4 = "0.0.0.0/0";
const FULL_TUNNEL_V6 = "::/0";

function isFullTunnel(v: string) {
  return v === FULL_TUNNEL_V4 || v === FULL_TUNNEL_V6;
}

export const CidrList = forwardRef<CidrListHandle, Props>(function CidrList(
  { value, onChange, placeholder, hint, warnFullTunnel = true, disallowFullTunnel = false },
  ref,
) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  function commit() {
    const v = draft.trim();
    if (!v) return;
    if (!CIDR_RE.test(v)) {
      setErr("Enter a CIDR like 10.0.0.0/24 or ::/0.");
      return;
    }
    if (disallowFullTunnel && isFullTunnel(v)) {
      setErr("0.0.0.0/0 and ::/0 aren't allowed here — they defeat per-peer source validation. Use the client routed networks field for full-tunnel routing.");
      return;
    }
    if (value.includes(v)) {
      setErr("Already added.");
      return;
    }
    onChange([...value, v]);
    setDraft("");
    setErr("");
  }

  // flush is the imperative escape hatch the parent submit path uses
  // so a pending draft never gets dropped on Save. We return the
  // canonical array synchronously (no waiting for setState to land)
  // and also fire onChange so the parent's state catches up for the
  // next render.
  useImperativeHandle(
    ref,
    () => ({
      flush(): string[] {
        const v = draft.trim();
        if (!v) return value;
        if (!CIDR_RE.test(v)) {
          setErr("Enter a CIDR like 10.0.0.0/24 or ::/0.");
          return value;
        }
        if (disallowFullTunnel && isFullTunnel(v)) {
          setErr("0.0.0.0/0 and ::/0 aren't allowed here — they defeat per-peer source validation. Use the client routed networks field for full-tunnel routing.");
          return value;
        }
        if (value.includes(v)) {
          setDraft("");
          return value;
        }
        const next = [...value, v];
        onChange(next);
        setDraft("");
        setErr("");
        return next;
      },
    }),
    [draft, value, onChange, disallowFullTunnel],
  );

  function remove(i: number) {
    onChange(value.filter((_, idx) => idx !== i));
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    // Enter and comma both append. Comma so an operator who's used to
    // typing comma-separated lists doesn't trip themselves.
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    }
  }

  const hasFullTunnel =
    warnFullTunnel &&
    (value.includes(FULL_TUNNEL_V4) || value.includes(FULL_TUNNEL_V6));

  return (
    <div className="space-y-2">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((v, i) => (
            <span
              key={`${v}-${i}`}
              className="inline-flex items-center gap-1.5 rounded-full bg-[var(--color-accent-soft,rgba(255,76,76,0.16))] text-[var(--color-text)] px-2.5 py-1 text-xs font-mono"
            >
              {v}
              <button
                type="button"
                onClick={() => remove(i)}
                aria-label={`Remove ${v}`}
                className="text-faint hover:text-[var(--color-danger)]"
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            if (err) setErr("");
          }}
          onKeyDown={onKeyDown}
          onBlur={() => draft.trim() && commit()}
          placeholder={placeholder ?? "10.0.0.0/24"}
          className="field-input flex-1"
        />
        <button type="button" onClick={commit} className="btn-ghost">
          + Add
        </button>
      </div>
      {err && <span className="field-hint text-danger">{err}</span>}
      {hint && !err && <span className="field-hint">{hint}</span>}
      {hasFullTunnel && (
        <span className="field-hint text-warning">
          Heads up — 0.0.0.0/0 routes <em>all</em> traffic through the
          tunnel. Make sure that's intended.
        </span>
      )}
    </div>
  );
});
