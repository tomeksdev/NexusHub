import type { ReactNode } from "react";

// RouteSection wraps a peer-route input (server-side or client-side)
// in a bordered, banner-headed card so the operator can never confuse
// the two fields. The banner sits flush at the top with a coloured
// accent stripe and a short "affects X" sentence — the surface a
// change here ends up on. Without this the two CidrList inputs look
// identical and operators have reported saving the wrong field; round
// 13 (this round) addresses that.
//
// `tone` picks the accent colour:
//   - "filter"  → server-side, uses the danger accent (red-ish)
//   - "routing" → client-side, uses the accent tone (neutral)
export function RouteSection({
  title,
  affects,
  tone,
  children,
}: {
  title: string;
  affects: string;
  tone: "filter" | "routing";
  children: ReactNode;
}) {
  const stripeColor =
    tone === "filter"
      ? "var(--color-danger, #ff4c4c)"
      : "var(--color-accent, #4c9eff)";
  return (
    <div
      className="rounded-md overflow-hidden"
      style={{
        border: "1px solid var(--color-line)",
        background: "rgba(255,255,255,0.02)",
      }}
    >
      <div
        className="px-3 py-2 flex items-center gap-3 text-xs"
        style={{
          borderBottom: "1px solid var(--color-line)",
          background: "rgba(255,255,255,0.04)",
        }}
      >
        <span
          aria-hidden
          style={{
            display: "inline-block",
            width: 4,
            height: 18,
            borderRadius: 2,
            background: stripeColor,
          }}
        />
        <div className="flex-1">
          <strong className="text-sm">{title}</strong>
          <div className="text-muted">{affects}</div>
        </div>
      </div>
      <div className="p-3 space-y-2">{children}</div>
    </div>
  );
}
