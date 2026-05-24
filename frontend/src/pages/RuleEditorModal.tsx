import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { PortField } from "../components/PortField";
import { ApiError, api } from "../lib/api";
import type { Rule } from "./RulesPage";

interface Props {
  // When editing, pass the rule; when creating, pass null.
  rule: Rule | null;
  onClose: () => void;
}

interface RulePayload {
  name: string;
  description?: string;
  action: string;
  direction: string;
  protocol: string;
  src_cidr?: string;
  dst_cidr?: string;
  src_port_from?: number;
  src_port_to?: number;
  dst_port_from?: number;
  dst_port_to?: number;
  rate_pps?: number;
  rate_burst?: number;
  priority?: number;
  is_active?: boolean;
}

const ACTIONS = ["allow", "deny", "rate_limit", "log"] as const;
const DIRECTIONS = ["ingress", "egress", "both"] as const;
const PROTOCOLS = ["any", "tcp", "udp", "icmp"] as const;

// Rate-limit + port inputs only apply to specific action/protocol combos.
// Keeping the logic here rather than disabling the fields means an edit
// that narrows the protocol clears stale port values on submit, matching
// what the backend would accept.
function protocolTakesPorts(p: string): boolean {
  return p === "tcp" || p === "udp";
}

// normalisePort converts the backend's "0 means wildcard" sentinel
// into undefined so the PortField component can express it as Any
// without leaking the magic number into the UI state.
function normalisePort(v: number | undefined): number | undefined {
  if (v == null || v === 0) return undefined;
  return v;
}

export function RuleEditorModal({ rule, onClose }: Props) {
  const qc = useQueryClient();
  const editing = rule !== null;

  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [action, setAction] = useState<string>(rule?.action ?? "deny");
  const [direction, setDirection] = useState<string>(
    rule?.direction ?? "ingress",
  );
  const [protocol, setProtocol] = useState<string>(rule?.protocol ?? "any");
  const [srcCIDR, setSrcCIDR] = useState(rule?.src_cidr ?? "");
  const [dstCIDR, setDstCIDR] = useState(rule?.dst_cidr ?? "");
  // Ports are kept as undefined ⇒ Any (backend stores 0..0). The
  // PortField component handles the Any/Single/Range UX; here we
  // just hold the resulting bounds. A stored 0..0 from an existing
  // rule is normalised to undefined for cleaner downstream logic.
  const [srcPortFrom, setSrcPortFrom] = useState<number | undefined>(
    normalisePort(rule?.src_port_from),
  );
  const [srcPortTo, setSrcPortTo] = useState<number | undefined>(
    normalisePort(rule?.src_port_to),
  );
  const [dstPortFrom, setDstPortFrom] = useState<number | undefined>(
    normalisePort(rule?.dst_port_from),
  );
  const [dstPortTo, setDstPortTo] = useState<number | undefined>(
    normalisePort(rule?.dst_port_to),
  );
  const [ratePPS, setRatePPS] = useState(rule?.rate_pps?.toString() ?? "");
  const [rateBurst, setRateBurst] = useState(
    rule?.rate_burst?.toString() ?? "",
  );
  const [priority, setPriority] = useState(rule?.priority?.toString() ?? "100");
  const [isActive, setIsActive] = useState(rule?.is_active ?? true);

  const mut = useMutation<Rule, ApiError>({
    mutationFn: () => {
      const body: RulePayload = {
        name: name.trim(),
        action,
        direction,
        protocol,
      };
      if (description.trim()) body.description = description.trim();
      if (srcCIDR.trim()) body.src_cidr = srcCIDR.trim();
      if (dstCIDR.trim()) body.dst_cidr = dstCIDR.trim();
      if (protocolTakesPorts(protocol)) {
        // Operator-facing Any maps to the backend's 0..0 sentinel.
        // Single (N) and Range (A..B) ship the literal numbers.
        body.src_port_from = srcPortFrom ?? 0;
        body.src_port_to = srcPortTo ?? 0;
        body.dst_port_from = dstPortFrom ?? 0;
        body.dst_port_to = dstPortTo ?? 0;
      }
      if (action === "rate_limit") {
        const pps = parseInt(ratePPS, 10);
        const burst = parseInt(rateBurst, 10);
        if (!Number.isNaN(pps)) body.rate_pps = pps;
        if (!Number.isNaN(burst)) body.rate_burst = burst;
      }
      const pr = parseInt(priority, 10);
      if (!Number.isNaN(pr)) body.priority = pr;
      body.is_active = isActive;

      const method = editing ? "PATCH" : "POST";
      const path = editing ? `/api/v1/rules/${rule!.id}` : "/api/v1/rules";
      return api<Rule>(path, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      onClose();
    },
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    mut.mutate();
  };

  return (
    <Modal
      title={editing ? `Edit rule: ${rule!.name}` : "New rule"}
      onClose={onClose}
    >
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <Field label="Name" required>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              maxLength={128}
              className="field-input"
            />
          </Field>
          <Field label="Priority (0–1000)">
            <input
              type="number"
              min={0}
              max={1000}
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              className="field-input"
            />
          </Field>
        </div>

        <Field label="Description">
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="field-input"
          />
        </Field>

        <div className="grid grid-cols-3 gap-4">
          <Field label="Action">
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="field-input"
            >
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Direction">
            <select
              value={direction}
              onChange={(e) => setDirection(e.target.value)}
              className="field-input"
            >
              {DIRECTIONS.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Protocol">
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="field-input"
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Source CIDR">
            <input
              type="text"
              placeholder="10.0.0.0/24"
              value={srcCIDR}
              onChange={(e) => setSrcCIDR(e.target.value)}
              className="field-input"
            />
          </Field>
          <Field label="Destination CIDR">
            <input
              type="text"
              placeholder="192.168.1.0/24"
              value={dstCIDR}
              onChange={(e) => setDstCIDR(e.target.value)}
              className="field-input"
            />
          </Field>
        </div>

        {protocolTakesPorts(protocol) && (
          <div className="grid grid-cols-2 gap-4">
            <PortField
              label="Source port"
              from={srcPortFrom}
              to={srcPortTo}
              onChange={(f, t) => {
                setSrcPortFrom(f);
                setSrcPortTo(t);
              }}
              idPrefix="src-port"
            />
            <PortField
              label="Destination port"
              from={dstPortFrom}
              to={dstPortTo}
              onChange={(f, t) => {
                setDstPortFrom(f);
                setDstPortTo(t);
              }}
              idPrefix="dst-port"
            />
          </div>
        )}

        {action === "rate_limit" && (
          <div className="grid grid-cols-2 gap-4">
            <Field label="Rate (packets/sec)" required>
              <input
                type="number"
                min={1}
                value={ratePPS}
                onChange={(e) => setRatePPS(e.target.value)}
                required
                className="field-input"
              />
            </Field>
            <Field label="Burst (optional)">
              <input
                type="number"
                min={0}
                value={rateBurst}
                onChange={(e) => setRateBurst(e.target.value)}
                className="field-input"
              />
            </Field>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm text-muted">
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e) => setIsActive(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          Active
        </label>

        {mut.isError && (
          <p className="text-danger text-sm">{(mut.error as Error).message}</p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || !name.trim()}
            className="btn-primary"
          >
            {mut.isPending ? "Saving…" : editing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="field-label">
      <span className="field-label-text">
        {label}
        {required && <span className="text-danger"> *</span>}
      </span>
      {children}
    </label>
  );
}
