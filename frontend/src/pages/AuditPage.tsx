import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";

interface AuditEntry {
  id: number;
  occurred_at: string;
  actor_user_id?: string | null;
  actor_ip?: string | null;
  actor_ua?: string | null;
  action: string;
  target_type: string;
  target_id?: string | null;
  metadata?: Record<string, unknown>;
  result: "success" | "failure" | "denied";
  error_message?: string | null;
}

const PAGE_SIZE = 50;

interface Filters {
  action: string;
  result: "" | "success" | "failure" | "denied";
  since: string;
}

export function AuditPage() {
  const [filters, setFilters] = useState<Filters>({
    action: "",
    result: "",
    since: "",
  });
  const [offset, setOffset] = useState(0);

  const qs = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", String(PAGE_SIZE));
    p.set("offset", String(offset));
    if (filters.action) p.set("action", filters.action);
    if (filters.result) p.set("result", filters.result);
    if (filters.since) {
      const iso = new Date(filters.since).toISOString();
      p.set("since", iso);
    }
    return p.toString();
  }, [filters, offset]);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["audit", qs],
    queryFn: () => api<PageEnvelope<AuditEntry>>(`/api/v1/audit-log?${qs}`),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const hasNext = offset + PAGE_SIZE < total;
  const hasPrev = offset > 0;

  function onFilterChange<K extends keyof Filters>(key: K, value: Filters[K]) {
    setFilters((f) => ({ ...f, [key]: value }));
    setOffset(0);
  }

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Audit log</h1>
        <span className="text-muted text-sm">{total} entries</span>
      </div>

      <div className="panel">
        <div className="flex flex-wrap gap-4 items-end">
          <label className="field-label" style={{ minWidth: "12rem" }}>
            <span className="field-label-text">Action</span>
            <input
              value={filters.action}
              onChange={(e) => onFilterChange("action", e.target.value)}
              placeholder="e.g. auth.login"
              className="field-input"
            />
          </label>
          <label className="field-label">
            <span className="field-label-text">Result</span>
            <select
              value={filters.result}
              onChange={(e) =>
                onFilterChange("result", e.target.value as Filters["result"])
              }
              className="field-input"
            >
              <option value="">any</option>
              <option value="success">success</option>
              <option value="failure">failure</option>
              <option value="denied">denied</option>
            </select>
          </label>
          <label className="field-label">
            <span className="field-label-text">Since</span>
            <input
              type="datetime-local"
              value={filters.since}
              onChange={(e) => onFilterChange("since", e.target.value)}
              className="field-input"
            />
          </label>
        </div>
      </div>

      {isLoading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : isError ? (
        <p className="text-danger text-sm">
          Failed to load: {(error as Error).message}
        </p>
      ) : items.length === 0 ? (
        <div className="panel">
          <p className="text-muted">No entries match the current filters.</p>
        </div>
      ) : (
        <div className="data-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Target</th>
                <th>Actor</th>
                <th>Result</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="text-muted whitespace-nowrap">
                    {new Date(e.occurred_at).toLocaleString()}
                  </td>
                  <td className="font-mono text-xs">{e.action}</td>
                  <td className="font-mono text-xs text-muted">
                    {e.target_type}
                    {e.target_id ? (
                      <span className="text-faint">:{shortID(e.target_id)}</span>
                    ) : null}
                  </td>
                  <td className="text-muted font-mono text-xs">
                    {e.actor_ip ??
                      (e.actor_user_id ? shortID(e.actor_user_id) : "—")}
                  </td>
                  <td>
                    <span className={resultBadge(e.result)}>
                      <span className="dot" />
                      {e.result.toUpperCase()}
                    </span>
                  </td>
                  <td className="text-faint text-xs truncate max-w-[30ch]">
                    {e.error_message ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex items-center justify-between text-sm">
        <span className="text-muted">
          {total === 0
            ? ""
            : `Showing ${offset + 1}–${Math.min(offset + items.length, total)} of ${total}`}
        </span>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
            disabled={!hasPrev}
            className="btn-ghost"
          >
            Previous
          </button>
          <button
            type="button"
            onClick={() => setOffset((o) => o + PAGE_SIZE)}
            disabled={!hasNext}
            className="btn-ghost"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

function resultBadge(r: string): string {
  if (r === "success") return "status-badge ok";
  if (r === "failure") return "status-badge critical";
  return "status-badge warning";
}

function shortID(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}
