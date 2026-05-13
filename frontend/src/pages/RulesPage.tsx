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
  // kernel_loaded reflects what the eBPF maps actually have right
  // now. Decoupled from is_active so the table can show the gap
  // when a rule is operator-enabled but the kernel never accepted
  // it (or the syncer is the noop).
  kernel_loaded?: boolean;
  // Live hit counters from the kernel's rule_hits map, summed
  // across CPUs. Undefined ⇒ syncer doesn't expose them (Noop, or
  // the rule has never matched a packet). Operator-facing column
  // helps answer "rule is LOADED but is it seeing traffic?".
  rule_hits_packets?: number;
  rule_hits_bytes?: number;
  // "admin" rules are operator-authored, fully editable, deletable.
  // "system" rules are auto-generated NexusHub baseline (cross-location
  // deny); operator can only toggle is_active. The list table shows a
  // "System" badge next to those and hides the Delete button.
  owner: "admin" | "system";
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

// HitsCell shows the kernel-side packets/bytes counter for the
// rule, summed across CPUs. Undefined → "—" (syncer doesn't
// expose the data, or the rule has never matched a packet).
// Zero with both fields present is rendered as "0" because that
// IS the actionable signal: the rule loaded but no packet
// hit it yet — useful when debugging "why isn't my deny working".
function HitsCell({ packets, bytes }: { packets?: number; bytes?: number }) {
  if (packets === undefined || bytes === undefined) {
    return <span className="text-faint">—</span>;
  }
  return (
    <span
      className="font-mono text-xs"
      title={`${packets.toLocaleString()} packets, ${bytes.toLocaleString()} bytes`}
    >
      {formatCount(packets)} pkts
      <span className="text-faint"> · {formatBytes(bytes)}</span>
    </span>
  );
}

function formatCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

// KernelBadge tells the operator whether the rule is actually
// programmed in the kernel maps. Three states:
//   - OK     : DB-active and kernel-loaded → enforced
//   - OFF    : DB-disabled → kernel intentionally empty
//   - ERROR  : DB-active but kernel doesn't have the rule (sync
//              failed silently or the API is running with NoopSyncer)
function KernelBadge({
  active,
  loaded,
}: {
  active: boolean;
  loaded: boolean;
}) {
  if (!active) {
    return (
      <span className="status-badge muted" title="Rule disabled in DB.">
        <span className="dot" />
        off
      </span>
    );
  }
  if (loaded) {
    return (
      <span className="status-badge ok" title="Rule is programmed in the kernel maps.">
        <span className="dot" />
        loaded
      </span>
    );
  }
  return (
    <span
      className="status-badge critical"
      title="Rule is enabled in the DB but the kernel hasn't loaded it. Check the eBPF stack on the Support page."
    >
      <span className="dot" />
      not loaded
    </span>
  );
}

// FilterPill renders a small toggle for the All / Admin / System
// owner filter. Active pill picks up the accent background; inactive
// is a flat ghost button.
function FilterPill({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={active ? "btn-primary" : "btn-ghost"}
      style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
    >
      {label}
    </button>
  );
}

// summarisePorts renders a port range for the rules table. The
// backend stores wildcard as 0..0; we present that as "Any" so the
// table reads as plain firewall language. Single-port rules show
// the literal number, ranges show A–B.
function summarisePorts(from?: number, to?: number): string {
  if (from == null && to == null) return "Any";
  if (from === 0 && to === 0) return "Any";
  if (from != null && to != null)
    return from === to ? `${from}` : `${from}–${to}`;
  return `${from ?? to ?? "Any"}`;
}

type OwnerFilter = "all" | "admin" | "system";

export function RulesPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Rule | null>(null);
  const [creating, setCreating] = useState(false);
  const [ownerFilter, setOwnerFilter] = useState<OwnerFilter>("all");

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["rules"],
    queryFn: () =>
      api<PageEnvelope<Rule>>("/api/v1/rules?limit=200&sort=-priority"),
    // 5 s refetch so the kernel-side hit counters tick visibly
    // when the operator is debugging "is this rule matching
    // anything". Quick enough to feel live, cheap enough that an
    // idle admin tab doesn't hammer the backend.
    refetchInterval: 5_000,
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

  // Sweep mutations — flip the entire owner='system' set at once. The
  // backend returns {flipped, active} so we know how many rows actually
  // changed and can show a useful confirmation.
  const sweepMut = useMutation<
    { flipped: number; active: boolean },
    Error,
    "enable-all" | "disable-all"
  >({
    mutationFn: (kind) =>
      api(`/api/v1/system-rules/${kind}`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const onDelete = (r: Rule) => {
    if (!confirm(`Delete rule "${r.name}"? This cannot be undone.`)) return;
    deleteMut.mutate(r.id);
  };

  const onEnableAllSystem = () => {
    if (
      !confirm(
        "Enable every system rule? This blocks cross-location traffic immediately. Existing peer connections in those directions will drop.",
      )
    )
      return;
    sweepMut.mutate("enable-all");
  };

  const onDisableAllSystem = () => {
    if (
      !confirm(
        "Disable every system rule? Cross-location traffic will flow freely until you re-enable.",
      )
    )
      return;
    sweepMut.mutate("disable-all");
  };

  if (isLoading)
    return <div className="p-6 text-muted">Loading rules…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const allItems = data?.items ?? [];
  const items = allItems.filter((r) => {
    if (ownerFilter === "all") return true;
    return r.owner === ownerFilter;
  });
  const systemCount = allItems.filter((r) => r.owner === "system").length;
  const adminCount = allItems.length - systemCount;

  return (
    <div className="space-y-6">
      <div className="topbar">
        <div>
          <h1 className="page-title">eBPF rules</h1>
          <p className="text-faint text-xs mt-1">
            Rules apply in descending priority order. System rules are
            auto-generated cross-location denies — toggle them on to
            enforce, off to allow free routing between locations.
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

      <div className="flex items-center gap-2 text-sm flex-wrap">
        <FilterPill
          label={`All (${allItems.length})`}
          active={ownerFilter === "all"}
          onClick={() => setOwnerFilter("all")}
        />
        <FilterPill
          label={`Admin (${adminCount})`}
          active={ownerFilter === "admin"}
          onClick={() => setOwnerFilter("admin")}
        />
        <FilterPill
          label={`System (${systemCount})`}
          active={ownerFilter === "system"}
          onClick={() => setOwnerFilter("system")}
        />
        {systemCount > 0 && (
          <div className="ml-auto inline-flex gap-2">
            <button
              type="button"
              onClick={onEnableAllSystem}
              disabled={sweepMut.isPending}
              className="btn-ghost"
              style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
              title="Flip is_active=true on every system rule"
            >
              Enable all system rules
            </button>
            <button
              type="button"
              onClick={onDisableAllSystem}
              disabled={sweepMut.isPending}
              className="btn-ghost"
              style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
              title="Flip is_active=false on every system rule"
            >
              Disable all
            </button>
          </div>
        )}
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
                <th>Kernel</th>
                <th>Hits</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="text-muted">{r.priority}</td>
                  <td>
                    <div className="font-medium flex items-center gap-2">
                      {r.name}
                      {r.owner === "system" && (
                        <span
                          className="status-badge muted text-[10px]"
                          title="Auto-generated NexusHub baseline. Toggle is_active to enforce; deletion is disabled."
                        >
                          system
                        </span>
                      )}
                    </div>
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
                  <td>
                    <KernelBadge
                      active={r.is_active}
                      loaded={!!r.kernel_loaded}
                    />
                  </td>
                  <td>
                    <HitsCell
                      packets={r.rule_hits_packets}
                      bytes={r.rule_hits_bytes}
                    />
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <div className="inline-flex gap-2">
                      {r.owner === "system" ? (
                        <span
                          className="text-faint text-xs"
                          title="System rules accept only is_active changes. Use the on/off toggle in the Active column."
                        >
                          toggle only
                        </span>
                      ) : (
                        <>
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
                        </>
                      )}
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
