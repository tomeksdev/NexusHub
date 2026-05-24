import { useState } from "react";

// PortField wraps the from/to integer pair the backend stores into
// three operator-friendly modes: Any (wildcard), Single (one port),
// and Range. Backend representation is unchanged — Any maps to
// from=0, to=0; Single maps to from=N, to=N; Range maps to
// from=A, to=B (A <= B).
//
// Component owns its own internal mode + draft state. The parent
// receives changes via onChange(from, to) where both values are
// either undefined (no constraint, equivalent to Any) or numbers
// in the 1..65535 range. The parent never sees 0; the conversion
// happens inside RuleEditorModal when building the request body.

export type PortMode = "any" | "single" | "range";

interface Props {
  // Initial from/to from the existing rule. Undefined means "Any".
  from?: number;
  to?: number;
  onChange: (from: number | undefined, to: number | undefined) => void;
  label?: string;
  // Visual id linkage so labels resolve correctly.
  idPrefix?: string;
}

function inferMode(from?: number, to?: number): PortMode {
  if (from == null && to == null) return "any";
  if (from === to) return "single";
  return "range";
}

export function PortField({ from, to, onChange, label, idPrefix }: Props) {
  const [mode, setMode] = useState<PortMode>(inferMode(from, to));
  const [single, setSingle] = useState<string>(
    mode === "single" && from != null ? String(from) : "",
  );
  const [rangeFrom, setRangeFrom] = useState<string>(
    mode === "range" && from != null ? String(from) : "",
  );
  const [rangeTo, setRangeTo] = useState<string>(
    mode === "range" && to != null ? String(to) : "",
  );
  const [err, setErr] = useState("");

  // The four useState initializers above already capture the
  // mount-time from/to values; after mount, internal state is the
  // source of truth and the parent shouldn't yank it. (An earlier
  // version did the same prop-sync via useEffect with [] deps —
  // redundant once the initializers were there.)

  function isPort(v: number) {
    return Number.isInteger(v) && v >= 1 && v <= 65535;
  }

  function applySingle(v: string) {
    setSingle(v);
    if (v === "") {
      setErr("");
      onChange(undefined, undefined);
      return;
    }
    const n = Number(v);
    if (!isPort(n)) {
      setErr("Port must be 1–65535.");
      return;
    }
    setErr("");
    onChange(n, n);
  }
  function applyRange(f: string, t: string) {
    setRangeFrom(f);
    setRangeTo(t);
    if (f === "" && t === "") {
      setErr("");
      onChange(undefined, undefined);
      return;
    }
    const fn = Number(f);
    const tn = Number(t);
    if (!isPort(fn) || !isPort(tn)) {
      setErr("From and To must each be 1–65535.");
      return;
    }
    if (fn > tn) {
      setErr("From must be ≤ To.");
      return;
    }
    setErr("");
    onChange(fn, tn);
  }
  function changeMode(next: PortMode) {
    setMode(next);
    setErr("");
    if (next === "any") {
      onChange(undefined, undefined);
    } else if (next === "single") {
      // Carry over the from value if there was a single port.
      if (single !== "") {
        const n = Number(single);
        if (isPort(n)) onChange(n, n);
        else onChange(undefined, undefined);
      } else {
        onChange(undefined, undefined);
      }
    } else {
      // Range: blank inputs → Any until the operator types.
      onChange(undefined, undefined);
    }
  }

  const modeId = idPrefix ? `${idPrefix}-mode` : undefined;

  return (
    <div className="space-y-2">
      {label && <span className="field-label-text inline-block">{label}</span>}
      <div className="flex items-center gap-2">
        <select
          id={modeId}
          value={mode}
          onChange={(e) => changeMode(e.target.value as PortMode)}
          className="field-input"
          style={{ maxWidth: "8rem" }}
        >
          <option value="any">Any</option>
          <option value="single">Single</option>
          <option value="range">Range</option>
        </select>
        {mode === "single" && (
          <input
            value={single}
            onChange={(e) => applySingle(e.target.value)}
            placeholder="22"
            inputMode="numeric"
            className="field-input"
            style={{ maxWidth: "10rem" }}
            aria-label="port"
          />
        )}
        {mode === "range" && (
          <>
            <input
              value={rangeFrom}
              onChange={(e) => applyRange(e.target.value, rangeTo)}
              placeholder="1000"
              inputMode="numeric"
              className="field-input"
              style={{ maxWidth: "8rem" }}
              aria-label="from port"
            />
            <span className="text-faint text-sm">to</span>
            <input
              value={rangeTo}
              onChange={(e) => applyRange(rangeFrom, e.target.value)}
              placeholder="2000"
              inputMode="numeric"
              className="field-input"
              style={{ maxWidth: "8rem" }}
              aria-label="to port"
            />
          </>
        )}
      </div>
      {err && <span className="field-hint text-danger">{err}</span>}
    </div>
  );
}
