import { useEffect, useState } from "react";

// useEscapeKey fires cb when the user presses Escape while the hook is
// mounted. Modals use this as the canonical "close" binding so every
// overlay in the app responds consistently without re-implementing the
// keydown listener.
export function useEscapeKey(cb: () => void): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        cb();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [cb]);
}

// useNowEveryMinute returns a client-side "now" that ticks once a
// minute so render branches depending on time-since-event (peer
// handshake freshness, lock expiry) refresh without making the
// render itself impure. One interval per hook instance — cheap at
// the current page count, and the tick stops when the component
// unmounts.
export function useNowEveryMinute(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);
  return now;
}
