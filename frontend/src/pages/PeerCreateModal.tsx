import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { CidrList, type CidrListHandle } from "../components/CidrList";
import { ConfigPreview } from "../components/ConfigPreview";
import { Modal } from "../components/Modal";
import { ThreeLayerCallout } from "../components/ThreeLayerCallout";
import { ApiError, api, type PageEnvelope } from "../lib/api";

interface Props {
  // Optional pre-selection for the location. The User detail page
  // passes a value here so the modal opens with the location
  // pre-filled. The picker stays editable so the operator can move
  // the peer to a different location before saving.
  interfaceID?: string;
  // Pre-selection for the user owner. The User detail page passes
  // both this and ownerLocked=true so the modal hides the user
  // picker entirely.
  ownerUserID?: string;
  ownerLocked?: boolean;
  onClose: () => void;
  onCreated: (peer: { id: string; name: string }) => void;
}

interface CreatePayload {
  interface_id: string;
  name: string;
  description?: string;
  assigned_ip?: string;
  allowed_ips?: string[];
  client_allowed_ips?: string[];
  endpoint?: string;
  dns?: string[];
  persistent_keepalive?: number;
  owner_user_id?: string;
}

interface PeerResponse {
  id: string;
  name: string;
}

interface UserListRow {
  id: string;
  email: string;
  username: string;
  is_active: boolean;
}

interface InterfaceRow {
  id: string;
  name: string;
  listen_port: number;
  address: string;
  endpoint?: string | null;
  dns: string[];
  mtu?: number | null;
}

export function PeerCreateModal({
  interfaceID,
  ownerUserID,
  ownerLocked,
  onClose,
  onCreated,
}: Props) {
  const qc = useQueryClient();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedIface, setSelectedIface] = useState<string>(interfaceID ?? "");
  const [assignedIP, setAssignedIP] = useState("");
  const [allowedIPs, setAllowedIPs] = useState<string[]>([]);
  const [clientAllowedIPs, setClientAllowedIPs] = useState<string[]>([]);
  const [keepalive, setKeepalive] = useState("");
  const [owner, setOwner] = useState<string>(ownerUserID ?? "");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [endpointOverride, setEndpointOverride] = useState("");
  const allowedRef = useRef<CidrListHandle>(null);
  const clientAllowedRef = useRef<CidrListHandle>(null);

  // Locations (interfaces) the operator can pick from. The label
  // shows "wgN — host:port" so it's clear what each option binds to.
  const ifacesQ = useQuery({
    queryKey: ["interfaces"],
    queryFn: () =>
      api<PageEnvelope<InterfaceRow>>("/api/v1/interfaces?limit=100"),
    staleTime: 60_000,
  });
  const ifaces = ifacesQ.data?.items ?? [];
  const selected = ifaces.find((i) => i.id === selectedIface);

  // First-render auto-pick: if no interfaceID was passed AND there's
  // exactly one location, select it. With multiple, leave the picker
  // empty so the operator makes an explicit choice.
  useEffect(() => {
    if (!selectedIface && ifaces.length === 1) {
      setSelectedIface(ifaces[0].id);
    }
  }, [ifaces, selectedIface]);

  // When the selection changes, fetch the suggested next-free IP and
  // pre-fill it. The user can override by typing.
  const nextIPQ = useQuery({
    queryKey: ["next-ip", selectedIface],
    queryFn: () =>
      api<{ assigned_ip: string }>(
        `/api/v1/interfaces/${selectedIface}/next-ip`,
      ),
    enabled: !!selectedIface,
    staleTime: 0,
    retry: false,
  });
  useEffect(() => {
    if (nextIPQ.data?.assigned_ip) {
      setAssignedIP(nextIPQ.data.assigned_ip);
    }
  }, [nextIPQ.data?.assigned_ip]);

  const usersQ = useQuery({
    queryKey: ["users-picker"],
    queryFn: () =>
      api<PageEnvelope<UserListRow>>("/api/v1/users?limit=200&sort=email"),
    enabled: !ownerLocked,
    staleTime: 60_000,
  });

  const mut = useMutation<PeerResponse, ApiError>({
    mutationFn: () => {
      // Force-commit any pending CidrList draft text so an operator
      // who typed a CIDR and clicked Save without pressing Enter
      // doesn't lose the network silently.
      const finalAllowed = allowedRef.current?.flush() ?? allowedIPs;
      const finalClientAllowed =
        clientAllowedRef.current?.flush() ?? clientAllowedIPs;

      const body: CreatePayload = {
        interface_id: selectedIface,
        name: name.trim(),
      };
      if (owner) body.owner_user_id = owner;
      if (description.trim()) body.description = description.trim();
      if (assignedIP.trim()) body.assigned_ip = assignedIP.trim();
      if (finalAllowed.length > 0) body.allowed_ips = finalAllowed;
      if (finalClientAllowed.length > 0)
        body.client_allowed_ips = finalClientAllowed;
      const ka = parseInt(keepalive, 10);
      if (!Number.isNaN(ka) && ka > 0) body.persistent_keepalive = ka;
      if (showAdvanced && endpointOverride.trim()) {
        body.endpoint = endpointOverride.trim();
      }
      return api<PeerResponse>("/api/v1/peers", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: (peer) => {
      qc.invalidateQueries({ queryKey: ["peers"] });
      qc.invalidateQueries({ queryKey: ["peers-by-owner"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      onCreated(peer);
    },
  });

  // Lightweight client-side validation of the assigned IP — the
  // backend re-checks, but failing here saves a round-trip and keeps
  // the operator from seeing a confusing 400 after submit. We trust
  // the dotted-quad shape; the deep checks (subnet membership,
  // network/broadcast) live on the server.
  const ipShape = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipInputErr =
    assignedIP.trim() && !ipShape.test(assignedIP.trim())
      ? "Enter an IPv4 address (e.g. 10.8.0.5)."
      : "";

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !selectedIface) return;
    mut.mutate();
  }

  const canSubmit =
    !mut.isPending && name.trim() !== "" && selectedIface !== "" && !ipInputErr;

  return (
    <Modal title="New peer" onClose={onClose} maxWidthClass="max-w-lg">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="alice-laptop"
            className="field-input"
            autoFocus
            required
          />
        </Field>

        <Field label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="optional"
            className="field-input"
          />
        </Field>

        <Field
          label="Location / Interface"
          hint="The peer inherits endpoint, network, DNS, and MTU from this location."
          required
        >
          {ifacesQ.isLoading ? (
            <p className="text-muted text-sm">Loading…</p>
          ) : ifaces.length === 0 ? (
            <p className="text-danger text-sm">
              No locations configured. Create one in the Locations page first.
            </p>
          ) : (
            <select
              value={selectedIface}
              onChange={(e) => {
                setSelectedIface(e.target.value);
                setAssignedIP(""); // re-trigger next-ip fetch
              }}
              className="field-input"
              required
            >
              {!selectedIface && <option value="">— pick a location —</option>}
              {ifaces.map((i) => {
                const ep = i.endpoint
                  ? i.endpoint
                  : `:${i.listen_port}`;
                return (
                  <option key={i.id} value={i.id}>
                    {i.name} — {ep}
                  </option>
                );
              })}
            </select>
          )}
        </Field>

        {!ownerLocked && (
          <Field
            label="Owner (user)"
            hint="Optional — links the peer to a user account."
          >
            <select
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              className="field-input"
            >
              <option value="">— unassigned —</option>
              {(usersQ.data?.items ?? [])
                .filter((u) => u.is_active)
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email} ({u.username})
                  </option>
                ))}
            </select>
          </Field>
        )}

        <Field
          label="Peer tunnel address (/32)"
          hint={
            selected
              ? `Inside ${selected.address}. Auto-suggested; edit if you want a specific address.`
              : "Pick a location first."
          }
        >
          <input
            value={assignedIP}
            onChange={(e) => setAssignedIP(e.target.value)}
            placeholder={
              nextIPQ.isLoading ? "loading suggestion…" : "10.8.0.5"
            }
            className="field-input"
            disabled={!selectedIface}
          />
          {assignedIP.trim() && !ipInputErr && (
            <span className="field-hint">
              Will be exported as{" "}
              <code className="font-mono">{assignedIP.trim()}/32</code>.
            </span>
          )}
          {ipInputErr && (
            <span className="field-hint text-danger">{ipInputErr}</span>
          )}
        </Field>

        <ThreeLayerCallout />

        <Field
          label="Server-side accepted source IPs"
          hint="Affects wg show. Source IPs the server accepts from this peer; the assigned /32 is auto-included on save."
        >
          <CidrList
            ref={allowedRef}
            value={allowedIPs}
            onChange={setAllowedIPs}
            placeholder="10.8.0.5/32"
            warnFullTunnel={false}
          />
        </Field>

        <Field
          label="Client routed networks (in exported .conf)"
          hint="Affects the peer's [Peer] AllowedIPs line. Networks the client routes THROUGH the tunnel. Empty ⇒ falls back to the location's CIDR (split-tunnel)."
        >
          <CidrList
            ref={clientAllowedRef}
            value={clientAllowedIPs}
            onChange={setClientAllowedIPs}
            placeholder="0.0.0.0/0"
          />
        </Field>

        <Field label="Persistent keepalive (seconds)">
          <input
            value={keepalive}
            onChange={(e) => setKeepalive(e.target.value)}
            placeholder="e.g. 25"
            inputMode="numeric"
            className="field-input"
          />
        </Field>

        <details
          open={showAdvanced}
          onToggle={(e) =>
            setShowAdvanced((e.currentTarget as HTMLDetailsElement).open)
          }
          className="border-t border-[var(--color-line)] pt-3"
        >
          <summary className="text-sm text-muted cursor-pointer select-none">
            Advanced options
          </summary>
          <div className="mt-3">
            <Field
              label="Endpoint override"
              hint="Leave blank to inherit from the location. Use only when this peer must reach a different endpoint than the location's default."
            >
              <input
                value={endpointOverride}
                onChange={(e) => setEndpointOverride(e.target.value)}
                placeholder={
                  selected?.endpoint
                    ? `inheriting ${selected.endpoint}`
                    : "vpn.example.com:51820"
                }
                className="field-input"
              />
            </Field>
          </div>
        </details>

        <ConfigPreview
          assignedIP={assignedIP}
          interfaceCIDR={selected?.address}
          clientAllowedIPs={clientAllowedIPs}
          endpointOverride={
            showAdvanced ? endpointOverride : ""
          }
          locationEndpoint={selected?.endpoint ?? null}
        />

        {mut.isError && (
          <p className="text-danger text-sm">
            {mut.error instanceof ApiError
              ? mut.error.message
              : "Failed to create peer"}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button type="submit" disabled={!canSubmit} className="btn-primary">
            {mut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <label className="field-label">
      <span className="field-label-text">
        {label}
        {required && <span className="text-danger ml-0.5">*</span>}
      </span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}
