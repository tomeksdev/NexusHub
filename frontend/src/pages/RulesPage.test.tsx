import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

import { clearTokens, setTokens } from "../lib/api";
import { server } from "../test/msw";
import { RulesPage } from "./RulesPage";

// RulesPage uses react-query under the hood and the api() helper which
// expects an access token in module-level state. Each test sets a fresh
// token + a fresh QueryClient so cached responses from a prior test
// can't bleed in. (#102)
beforeEach(() => {
  clearTokens();
  setTokens("test-access", new Date(Date.now() + 600_000).toISOString(), "rt");
});

function renderWithClient(ui: React.ReactElement) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("RulesPage null-field defense (#102)", () => {
  it("renders the enforcement-off banner when missing_features is null", async () => {
    server.use(
      http.get("/api/v1/diag/ebpf", () =>
        HttpResponse.json({
          programs: null,
          pin_path: "",
          loader: {
            loaded: false,
            error: "loader init failed: permission denied",
            capabilities_ok: true,
            // The Go backend's defensive layer should make this an
            // empty array, but the test pins what happens if it ever
            // regresses to a raw nil slice.
            missing_features: null,
            permission_denied: false,
            last_attempt_at: "2026-06-07T11:00:00Z",
          },
        }),
      ),
      http.get("/api/v1/rules", () =>
        HttpResponse.json({
          items: [],
          total: 0,
          limit: 200,
          offset: 0,
        }),
      ),
    );

    renderWithClient(<RulesPage />);

    await waitFor(() => {
      expect(screen.getByText("ENFORCEMENT OFF")).toBeInTheDocument();
    });
    expect(
      screen.getByText(/eBPF rule engine could not load/),
    ).toBeInTheDocument();
    // Empty rules list still renders the explicit empty state, not a
    // blank page.
    expect(screen.getByText(/No rules yet/)).toBeInTheDocument();
  });

  it("renders the empty state when /rules returns items: null", async () => {
    server.use(
      http.get("/api/v1/diag/ebpf", () =>
        HttpResponse.json({
          programs: [],
          pin_path: "/sys/fs/bpf/nexushub",
          loader: {
            loaded: true,
            capabilities_ok: true,
            missing_features: [],
            permission_denied: false,
            last_attempt_at: "2026-06-07T11:00:00Z",
          },
        }),
      ),
      http.get("/api/v1/rules", () =>
        HttpResponse.json({
          // The Page envelope from the backend is initialized to [],
          // but pin what the page does if it ever sees null.
          items: null,
          total: 0,
          limit: 200,
          offset: 0,
        }),
      ),
    );

    renderWithClient(<RulesPage />);

    await waitFor(() => {
      expect(screen.getByText(/No rules yet/)).toBeInTheDocument();
    });
    // No enforcement banner because the loader is healthy.
    expect(screen.queryByText("ENFORCEMENT OFF")).not.toBeInTheDocument();
  });

  it("renders the missing-features hint when a real feature is missing", async () => {
    server.use(
      http.get("/api/v1/diag/ebpf", () =>
        HttpResponse.json({
          programs: [],
          pin_path: "",
          loader: {
            loaded: false,
            error: "bpf_loop helper not available",
            capabilities_ok: false,
            missing_features: ["bpf_loop"],
            permission_denied: false,
            last_attempt_at: "2026-06-07T11:00:00Z",
          },
        }),
      ),
      http.get("/api/v1/rules", () =>
        HttpResponse.json({ items: [], total: 0, limit: 200, offset: 0 }),
      ),
    );

    renderWithClient(<RulesPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/Kernel features missing: bpf_loop/),
      ).toBeInTheDocument();
    });
  });
});
