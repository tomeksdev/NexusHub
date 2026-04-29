// Minimal Prometheus text-format parser. We only support the shapes the
// backend actually emits today (counters, gauges, histogram buckets with
// `le` labels); summaries are out of scope.
//
// Full grammar reference:
// https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md

export interface PromSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export function parseProm(text: string): PromSample[] {
  const out: PromSample[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    // name{label="v",...} value [timestamp]
    // or: name value
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)/.exec(t);
    if (!m) continue;
    const [, name, rawLabels, rawVal] = m;
    const v = Number(rawVal);
    if (!Number.isFinite(v)) continue;
    out.push({ name, labels: parseLabels(rawLabels ?? ""), value: v });
  }
  return out;
}

function parseLabels(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!s) return out;
  // Values may contain escaped quotes; the exposition format restricts
  // escapes to \" \\ \n so a minimal state walker beats a regex.
  let i = 0;
  while (i < s.length) {
    while (i < s.length && (s[i] === "," || s[i] === " ")) i++;
    const eq = s.indexOf("=", i);
    if (eq < 0) break;
    const key = s.slice(i, eq).trim();
    if (s[eq + 1] !== '"') break;
    let j = eq + 2;
    let val = "";
    while (j < s.length && s[j] !== '"') {
      if (s[j] === "\\" && j + 1 < s.length) {
        const next = s[j + 1];
        val += next === "n" ? "\n" : next;
        j += 2;
        continue;
      }
      val += s[j];
      j++;
    }
    out[key] = val;
    i = j + 1;
  }
  return out;
}

// sum aggregates samples whose name matches and whose labels satisfy `match`.
export function sum(
  samples: PromSample[],
  name: string,
  match: (labels: Record<string, string>) => boolean = () => true,
): number {
  let total = 0;
  for (const s of samples) {
    if (s.name !== name) continue;
    if (!match(s.labels)) continue;
    total += s.value;
  }
  return total;
}

// value returns the first sample matching name + labels, or undefined.
export function value(
  samples: PromSample[],
  name: string,
  match: (labels: Record<string, string>) => boolean = () => true,
): number | undefined {
  for (const s of samples) {
    if (s.name === name && match(s.labels)) return s.value;
  }
  return undefined;
}
