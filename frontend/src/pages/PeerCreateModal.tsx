import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { ApiError, api, type PageEnvelope } from "../lib/api";

interface Props {
  interfaceID: string;
  // Optional pre-selection. The User detail page passes this so the
  // modal opens with the owner already chosen and the picker hidden.
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

interface UserListRow {
  id: string;
  email: string;
  username: string;
  is_active: boolean;
}

interface PeerResponse {
  id: string;
  name: string;
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
  const [assignedIP, setAssignedIP] = useState("");
  const [allowedIPs, setAllowedIPs] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [keepalive, setKeepalive] = useState("");
  const [clientAllowedIPs, setClientAllowedIPs] = useState("");
  const [owner, setOwner] = useState<string>(ownerUserID ?? "");

  // Pull the user list for the dropdown. Admin-only endpoint; the
  // PeerCreateModal is itself admin-gated so this is fine. If the
  // operator has hundreds of users we'd want a typeahead, but at the
  // current scale a 100-row dropdown is the simpler shape.
  const usersQ = useQuery({
    queryKey: ["users-picker"],
    queryFn: () =>
      api<PageEnvelope<UserListRow>>("/api/v1/users?limit=200&sort=email"),
    // Don't reach for the user list when we already know who owns it.
    enabled: !ownerLocked,
    staleTime: 60_000,
  });

  const mut = useMutation<PeerResponse, ApiError>({
    mutationFn: () => {
      const body: CreatePayload = { interface_id: interfaceID, name };
      if (owner) body.owner_user_id = owner;
      if (description.trim()) body.description = description.trim();
      if (assignedIP.trim()) body.assigned_ip = assignedIP.trim();
      // allowed_ips is comma-separated in the UI; split + trim so the user
      // can paste "10.0.0.0/24, 10.1.0.0/16" without shape gymnastics.
      const ips = allowedIPs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (ips.length > 0) body.allowed_ips = ips;
      const clientIPs = clientAllowedIPs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (clientIPs.length > 0) body.client_allowed_ips = clientIPs;
      if (endpoint.trim()) body.endpoint = endpoint.trim();
      const ka = parseInt(keepalive, 10);
      if (!Number.isNaN(ka) && ka > 0) body.persistent_keepalive = ka;
      return api<PeerResponse>("/api/v1/peers", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: (peer) => {
      qc.invalidateQueries({ queryKey: ["peers"] });
      onCreated(peer);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    mut.mutate();
  }

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
        {!ownerLocked && (
          <Field label="Owner (user)" hint="Optional — links the peer to a user account.">
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
        <Field label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="optional"
            className="field-input"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Assigned IP">
            <input
              value={assignedIP}
              onChange={(e) => setAssignedIP(e.target.value)}
              placeholder="auto-allocate"
              className="field-input"
            />
          </Field>
          <Field label="Persistent keepalive (s)">
            <input
              value={keepalive}
              onChange={(e) => setKeepalive(e.target.value)}
              placeholder="e.g. 25"
              inputMode="numeric"
              className="field-input"
            />
          </Field>
        </div>
        <Field
          label="Allowed IPs (server-side)"
          hint="Source IPs the server accepts from this peer. Defaults to the assigned /32."
        >
          <input
            value={allowedIPs}
            onChange={(e) => setAllowedIPs(e.target.value)}
            placeholder="10.0.0.0/24, 10.1.0.0/16"
            className="field-input"
          />
        </Field>
        <Field
          label="Client AllowedIPs (in exported .conf)"
          hint="Destinations the peer routes through the tunnel. Empty ⇒ interface CIDR (split-tunnel). Use 0.0.0.0/0, ::/0 for full-tunnel."
        >
          <input
            value={clientAllowedIPs}
            onChange={(e) => setClientAllowedIPs(e.target.value)}
            placeholder="0.0.0.0/0, ::/0"
            className="field-input"
          />
        </Field>
        <Field
          label="Endpoint"
          hint="Override the interface endpoint for this peer."
        >
          <input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="vpn.example.com:51820"
            className="field-input"
          />
        </Field>

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
          <button
            type="submit"
            disabled={mut.isPending || !name.trim()}
            className="btn-primary"
          >
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
  children: React.ReactNode;
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
