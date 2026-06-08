import { Component, type ReactNode } from "react";

// PageErrorBoundary catches render errors inside a routed page so a
// single broken page doesn't blank the whole SPA. Without it, an
// unguarded null deref (see #102) takes down navigation too — the
// operator can't even reach Support to read the diagnostic. We log
// the error to the console so it still surfaces in the browser
// devtools without users having to enable React StrictMode.
interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class PageErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: { componentStack?: string | null }) {
    // eslint-disable-next-line no-console
    console.error("page render crashed", error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (!this.state.error) return this.props.children;
    const msg = this.state.error.message || String(this.state.error);
    return (
      <div className="p-6 space-y-4 max-w-2xl">
        <div className="panel border border-danger/60 bg-danger/5 space-y-3">
          <div className="flex items-center gap-2">
            <span className="status-badge critical">
              <span className="dot" />
              PAGE CRASHED
            </span>
            <span className="text-danger font-medium">
              This page hit a render error.
            </span>
          </div>
          <p className="text-sm text-muted">
            Other pages are still reachable from the sidebar. The error is
            logged to the browser console — open DevTools for the full stack.
            Sharing it on the issue tracker helps us patch the regression.
          </p>
          <details className="text-xs">
            <summary className="text-faint cursor-pointer">
              Error message
            </summary>
            <pre className="mt-2 text-xs text-muted font-mono whitespace-pre-wrap">
              {msg}
            </pre>
          </details>
          <button type="button" onClick={this.reset} className="btn-ghost">
            Retry this page
          </button>
        </div>
      </div>
    );
  }
}
