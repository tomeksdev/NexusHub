import { describe, expect, it } from "vitest";

import {
  actionBadgeClass,
  formatBytes,
  formatCount,
  isPlaceholderHandshake,
  summarisePorts,
} from "./format";

describe("formatCount", () => {
  it("returns raw count under 1000", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(999)).toBe("999");
  });

  it("rounds to k between 1000 and 1M", () => {
    expect(formatCount(1000)).toBe("1.0k");
    expect(formatCount(1500)).toBe("1.5k");
    expect(formatCount(999_999)).toBe("1000.0k");
  });

  it("rounds to M above 1M", () => {
    expect(formatCount(1_000_000)).toBe("1.0M");
    expect(formatCount(2_500_000)).toBe("2.5M");
  });
});

describe("formatBytes", () => {
  it("uses bytes below 1 KiB", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
  });

  it("uses KiB below 1 MiB", () => {
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1024 * 1024 - 1)).toMatch(/KiB$/);
  });

  it("uses MiB below 1 GiB", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MiB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MiB");
  });

  it("uses GiB above 1 GiB", () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GiB");
    expect(formatBytes(2.5 * 1024 * 1024 * 1024)).toBe("2.50 GiB");
  });
});

describe("summarisePorts", () => {
  it("renders Any for both nil", () => {
    expect(summarisePorts(undefined, undefined)).toBe("Any");
  });

  it("renders Any for explicit 0/0 wildcard", () => {
    expect(summarisePorts(0, 0)).toBe("Any");
  });

  it("renders single port when from == to", () => {
    expect(summarisePorts(443, 443)).toBe("443");
  });

  it("renders range with en-dash when from != to", () => {
    expect(summarisePorts(1024, 65535)).toBe("1024–65535");
  });

  it("renders single value when only one side is set", () => {
    expect(summarisePorts(80, undefined)).toBe("80");
    expect(summarisePorts(undefined, 443)).toBe("443");
  });
});

describe("actionBadgeClass", () => {
  it("maps every action to a class", () => {
    expect(actionBadgeClass("allow")).toContain("ok");
    expect(actionBadgeClass("deny")).toContain("critical");
    expect(actionBadgeClass("rate_limit")).toContain("warning");
    expect(actionBadgeClass("log")).toContain("muted");
  });
});

describe("isPlaceholderHandshake", () => {
  it("treats nil / empty as placeholder", () => {
    expect(isPlaceholderHandshake(null)).toBe(true);
    expect(isPlaceholderHandshake(undefined)).toBe(true);
    expect(isPlaceholderHandshake("")).toBe(true);
  });

  it("treats the Go zero-time prefix as placeholder", () => {
    expect(isPlaceholderHandshake("0001-01-01T00:00:00Z")).toBe(true);
  });

  it("treats a real RFC-3339 timestamp as a real handshake", () => {
    expect(isPlaceholderHandshake("2026-05-18T09:00:00Z")).toBe(false);
  });
});
