// Pure formatting helpers shared by the Rules + Peers tables. Lifted
// out of the page components so they can be unit-tested without
// mounting React — the page-level components hit a 0% coverage wall
// otherwise (vitest counts only what gets imported and exercised, so
// keeping these as page-internal `function fooXyz()` declarations
// hides them from the suite even when the rendered table calls them
// every test run).

// formatCount renders an integer like 1234 → "1.2k", 1500000 → "1.5M".
// Returns the raw number below 1000 so single-digit counters don't
// pick up a decimal point.
export function formatCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

// formatBytes renders a byte count with the largest matching unit. Stops
// at GiB since anything bigger should already be on a different table.
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

// summarisePorts renders a port range for the rules table. The backend
// stores wildcard as 0..0; we present that as "Any" so the table reads
// as plain firewall language. Single-port rules show the literal number;
// ranges show A–B.
export function summarisePorts(from?: number, to?: number): string {
  if (from == null && to == null) return "Any";
  if (from === 0 && to === 0) return "Any";
  if (from != null && to != null) {
    return from === to ? `${from}` : `${from}–${to}`;
  }
  return `${from ?? to ?? "Any"}`;
}

// actionBadgeClass maps a rule action enum to a status-badge CSS class.
// Centralised so the Rules table and any future rule-summary card pick
// up the same colour vocabulary.
export type RuleAction = "allow" | "deny" | "rate_limit" | "log";

export function actionBadgeClass(a: RuleAction): string {
  switch (a) {
    case "allow":
      return "status-badge ok";
    case "deny":
      return "status-badge critical";
    case "rate_limit":
      return "status-badge warning";
    case "log":
      return "status-badge muted";
  }
}

// isPlaceholderHandshake decides whether a peer's `last_handshake`
// timestamp is the Go zero value (1-Jan-0001) the backend hands back
// for peers that have never handshook. The table renders those as
// "never" instead of an absurd "2025 years ago".
export function isPlaceholderHandshake(s: string | null | undefined): boolean {
  if (!s) return true;
  return s.startsWith("0001-");
}
