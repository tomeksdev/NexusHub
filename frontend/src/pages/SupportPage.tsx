import { useQuery } from "@tanstack/react-query";

import { api } from "../lib/api";

interface Health {
  status: string;
  version?: string;
  commit?: string;
}

export function SupportPage() {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => api<Health>("/api/v1/health"),
    retry: false,
    staleTime: 60_000,
  });

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="topbar">
        <h1 className="page-title">Support</h1>
      </div>

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">System</span>
          {data?.status === "ok" ? (
            <span className="status-badge ok">
              <span className="dot" />
              HEALTHY
            </span>
          ) : (
            <span className="status-badge muted">
              <span className="dot" />
              UNKNOWN
            </span>
          )}
        </div>
        <dl className="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
          <dt className="text-muted">Version</dt>
          <dd className="font-mono">{data?.version ?? "—"}</dd>
          <dt className="text-muted">Build</dt>
          <dd className="font-mono text-faint">{data?.commit ?? "—"}</dd>
        </dl>
      </section>

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">Documentation</span>
        </div>
        <ul className="space-y-2 text-sm">
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub#readme"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Getting started
            </a>
          </li>
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub/blob/main/docs/user-guide/README.md"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Admin guide
            </a>
          </li>
          <li>
            <a
              href="/api/v1/openapi.yaml"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              API reference (OpenAPI)
            </a>
          </li>
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub/issues"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Report a bug
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
