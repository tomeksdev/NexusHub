import { useState, type KeyboardEvent } from "react";

// Cheap client-side CIDR shape check. The deep validity (mask range,
// trailing zeros) is the server's job — this only catches typos
// before round-tripping a 400.
const CIDR_RE = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

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
}

const FULL_TUNNEL_V4 = "0.0.0.0/0";
const FULL_TUNNEL_V6 = "::/0";

export function CidrList({
  value,
  onChange,
  placeholder,
  hint,
  warnFullTunnel = true,
}: Props) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  function commit() {
    const v = draft.trim();
    if (!v) return;
    if (!CIDR_RE.test(v)) {
      setErr("Enter a CIDR like 10.0.0.0/24 or ::/0.");
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
}
