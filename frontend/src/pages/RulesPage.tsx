import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { RuleEditorModal } from "./RuleEditorModal";

export interface Rule {
  id: string;
  name: string;
  description?: string;
  action: "allow" | "deny" | "rate_limit" | "log";
  direction: "ingress" | "egress" | "both";
  protocol: "any" | "tcp" | "udp" | "icmp";
  src_cidr?: string;
  dst_cidr?: string;
  src_port_from?: number;
  src_port_to?: number;
  dst_port_from?: number;
  dst_port_to?: number;
  rate_pps?: number;
  rate_burst?: number;
  priority: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

function actionBadgeClass(a: Rule["action"]): string {
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

function summarisePorts(from?: number, to?: number): string {
  if (from == null && to == null) return "*";
  if (from != null && to != null)
    return from === to ? `${from}` : `${from}-${to}`;
  return `${from ?? to ?? "*"}`;
}

export function RulesPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Rule | null>(null);
  const [creating, setCreating] = useState(false);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["rules"],
    queryFn: () =>
      api<PageEnvelope<Rule>>("/api/v1/rules?limit=200&sort=-priority"),
  });

  const toggleMut = useMutation({
    mutationFn: (r: Rule) =>
      api(`/api/v1/rules/${r.id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: !r.is_active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      api(`/api/v1/rules/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const onDelete = (r: Rule) => {
    if (!confirm(`Delete rule "${r.name}"? This cannot be undone.`)) return;
    deleteMut.mutate(r.id);
  };

  if (isLoading)
    return <div className="p-6 text-muted">Loading rules…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const items = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="topbar">
        <div>
          <h1 className="page-title">eBPF rules</h1>
          <p className="text-faint text-xs mt-1">
            Rules apply in descending priority order.
          </p>
        </div>
        <div className="topbar-actions">
          <span className="text-muted text-sm">{data?.total ?? 0} total</span>
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="btn-primary"
          >
            + New rule
          </button>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="panel">
          <p className="text-muted">
            No rules yet. Click <strong>New rule</strong> to create the first.
          </p>
        </div>
      ) : (
        <div className="data-table">
          <table>
            <thead>
              <tr>
                <th>Priority</th>
                <th>Name</th>
                <th>Action</th>
                <th>Direction</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Active</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="text-muted">{r.priority}</td>
                  <td>
                    <div className="font-medium">{r.name}</div>
                    {r.description && (
                      <div className="text-faint text-xs">{r.description}</div>
                    )}
                  </td>
                  <td>
                    <span className={actionBadgeClass(r.action)}>
                      <span className="dot" />
                      {r.action}
                      {r.action === "rate_limit" && r.rate_pps && (
                        <span className="ml-1">{r.rate_pps}/s</span>
                      )}
                    </span>
                  </td>
                  <td className="text-muted">{r.direction}</td>
                  <td className="text-muted">
                    {r.protocol}
                    {(r.protocol === "tcp" || r.protocol === "udp") && (
                      <span className="text-faint text-xs ml-1">
                        :{summarisePorts(r.src_port_from, r.src_port_to)}→
                        {summarisePorts(r.dst_port_from, r.dst_port_to)}
                      </span>
                    )}
                  </td>
                  <td className="font-mono text-xs text-muted">
                    {r.src_cidr ?? <span className="text-faint">any</span>}
                  </td>
                  <td className="font-mono text-xs text-muted">
                    {r.dst_cidr ?? <span className="text-faint">any</span>}
                  </td>
                  <td>
                    <button
                      type="button"
                      onClick={() => toggleMut.mutate(r)}
                      disabled={toggleMut.isPending}
                      className={
                        r.is_active ? "status-badge ok" : "status-badge muted"
                      }
                    >
                      <span className="dot" />
                      {r.is_active ? "on" : "off"}
                    </button>
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <div className="inline-flex gap-2">
                      <button
                        type="button"
                        onClick={() => setEditing(r)}
                        className="btn-ghost"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(r)}
                        className="btn-danger"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {creating && (
        <RuleEditorModal rule={null} onClose={() => setCreating(false)} />
      )}
      {editing && (
        <RuleEditorModal rule={editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}
