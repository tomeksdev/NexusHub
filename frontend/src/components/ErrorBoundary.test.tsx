import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PageErrorBoundary } from "./ErrorBoundary";

function Boom(): React.ReactElement {
  throw new Error("kaboom");
}

describe("PageErrorBoundary", () => {
  it("renders the crash UI when a child throws", () => {
    // Silence React's noisy uncaught-error log so the test output
    // stays readable. The boundary itself still console.errors.
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <PageErrorBoundary>
        <Boom />
      </PageErrorBoundary>,
    );
    expect(screen.getByText("PAGE CRASHED")).toBeInTheDocument();
    expect(
      screen.getByText(/This page hit a render error/),
    ).toBeInTheDocument();
    expect(screen.getByText("kaboom")).toBeInTheDocument();
    spy.mockRestore();
  });

  it("renders children unchanged when nothing throws", () => {
    render(
      <PageErrorBoundary>
        <div data-testid="ok">healthy</div>
      </PageErrorBoundary>,
    );
    expect(screen.getByTestId("ok")).toHaveTextContent("healthy");
    expect(screen.queryByText("PAGE CRASHED")).not.toBeInTheDocument();
  });
});
