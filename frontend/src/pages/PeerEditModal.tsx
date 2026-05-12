import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { CidrList, type CidrListHandle } from "../components/CidrList";
import { ConfigPreview } from "../components/ConfigPreview";
import { Modal } from "../components/Modal";
import { ThreeLayerCallout } from "../components/ThreeLayerCallout";
import { ApiError, api, type PageEnvelope } from "../lib/api";

// Shape we accept — mirrors the peerResponse shape returned by the
// backend. Optional fields stay nullable so the form can show the
// current value (or an empty input when null).
export interface EditablePeer {
  id: string;
  interface_id: string;
  owner_user_id?: string | null;
  name: string;
  description?: string | null;
  allowed_ips: string[];
  client_allowed_ips: string[];
  assigned_ip: string;
  endpoint?: string | null;
  persistent_keepalive?: number | null;
  status: string;
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
  address: string;
  endpoint?: string | null;
}

interface Props {
  peer: EditablePeer;
  onClose: () => void;
  onSaved: () => void;
}

// Pointer-to-pointer JSON is awkward in TS; we model the same
// "leave-alone vs. clear vs. set" trichotomy by only including
// fields whose form value differs from the original peer.
type Patch = Partial<{
  name: string;
  description: string | null;
  owner_user_id: string | null;
  allowed_ips: string[];
  client_allowed_ips: string[];
  endpoint: string | null;
  persistent_keepalive: number | null;
  status: string;
}>;

export function PeerEditModal({ peer, onClose, onSaved }: Props) {
  const qc = useQueryClient();
  const [name, setName] = useState(peer.name);
  const [description, setDescription] = useState(peer.description ?? "");
  const [owner, setOwner] = useState<string>(peer.owner_user_id ?? "");
  const [allowedIPs, setAllowedIPs] = useState<string[]>(peer.allowed_ips);
  const [clientAllowedIPs, setClientAllowedIPs] = useState<string[]>(
    peer.client_allowed_ips,
  );
  const [endpoint, setEndpoint] = useState(peer.endpoint ?? "");
  const [keepalive, setKeepalive] = useState(
    peer.persistent_keepalive != null ? String(peer.persistent_keepalive) : "",
  );
  const [enabled, setEnabled] = useState(peer.status !== "disabled");
  const allowedRef = useRef<CidrListHandle>(null);
  const clientAllowedRef = useRef<CidrListHandle>(null);

  const usersQ = useQuery({
    queryKey: ["users-picker"],
    queryFn: () =>
      api<PageEnvelope<UserListRow>>("/api/v1/users?limit=200&sort=email"),
    staleTime: 60_000,
    retry: false,
  });
  const ifacesQ = useQuery({
    queryKey: ["interfaces"],
    queryFn: () =>
      api<PageEnvelope<InterfaceRow>>("/api/v1/interfaces?limit=100"),
    staleTime: 60_000,
  });
  const ownIface = (ifacesQ.data?.items ?? []).find(
    (i) => i.id === peer.interface_id,
  );

  const mut = useMutation<unknown, ApiError>({
    mutationFn: () => {
      // Commit any pending CidrList draft so a Save click before
      // the operator pressed Enter/+ Add doesn't drop the typed
      // network. flush() returns the canonical array synchronously
      // (state updates lag a render).
      const finalAllowed = allowedRef.current?.flush() ?? allowedIPs;
      const finalClientAllowed =
        clientAllowedRef.current?.flush() ?? clientAllowedIPs;

      const body: Patch = {};
      const trimmedName = name.trim();
      if (trimmedName !== peer.name) body.name = trimmedName;

      const desc = description.trim();
      const origDesc = peer.description ?? "";
      if (desc !== origDesc) body.description = desc === "" ? null : desc;

      const origOwner = peer.owner_user_id ?? "";
      if (owner !== origOwner) body.owner_user_id = owner === "" ? null : owner;

      // Always send the network arrays as a full snapshot. We used to
      // diff against `peer.*` and omit the field on a match, but that
      // skipped the write whenever the parent's `peer` prop was stale
      // relative to the form's local state (eg. modal opened before a
      // background refetch landed). Sending the snapshot every time
      // means the backend always sees the operator's current intent
      // — the kernel WG module is idempotent on reapply, so the cost
      // is zero. Backend auto-includes the assigned /32 in AllowedIPs
      // so an empty server-side list isn't a foot-gun either.
      body.allowed_ips = finalAllowed;
      body.client_allowed_ips = finalClientAllowed;

      const ep = endpoint.trim();
      const origEp = peer.endpoint ?? "";
      if (ep !== origEp) body.endpoint = ep === "" ? null : ep;

      const kaNum = keepalive.trim() === "" ? null : parseInt(keepalive, 10);
      const origKa = peer.persistent_keepalive ?? null;
      if (kaNum !== origKa) body.persistent_keepalive = kaNum;

      const desiredStatus = enabled ? "enabled" : "disabled";
      if (desiredStatus !== peer.status) body.status = desiredStatus;

      return api(`/api/v1/peers/${peer.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["peers"] });
      qc.invalidateQueries({ queryKey: ["peers-by-owner"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      onSaved();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    mut.mutate();
  }

  return (
    <Modal
      title={`Edit ${peer.name}`}
      description={`Assigned IP ${peer.assigned_ip} (read-only).`}
      onClose={onClose}
      maxWidthClass="max-w-lg"
    >
      <form onSubmit={submit} className="space-y-4">
        {/* Location + inherited endpoint context, shown read-only at
            the top so the operator never wonders "what does 'leave
            blank to inherit' actually inherit". */}
        <div
          className="rounded-md p-3 text-sm"
          style={{
            background: "rgba(255,255,255,0.04)",
            border: "1px solid var(--color-line)",
          }}
        >
          <dl className="grid grid-cols-[8rem_1fr] gap-y-1">
            <dt className="text-muted">Location</dt>
            <dd className="font-mono">
              {ownIface?.name ?? (
                <span className="text-faint">unknown</span>
              )}
            </dd>
            <dt className="text-muted">Inherited endpoint</dt>
            <dd className="font-mono">
              {ownIface?.endpoint ? (
                ownIface.endpoint
              ) : (
                <span className="text-faint">
                  (no endpoint configured on this location)
                </span>
              )}
            </dd>
          </dl>
        </div>

        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="field-input"
            required
            autoFocus
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
        <Field label="Owner (user)">
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

        <ThreeLayerCallout />

        <Field
          label="Server-side accepted source IPs"
          hint="Affects wg show. The kernel WG module accepts decrypted packets from this peer only when their source falls inside one of these CIDRs. The peer's assigned /32 is auto-included on save."
        >
          <CidrList
            ref={allowedRef}
            value={allowedIPs}
            onChange={setAllowedIPs}
            placeholder="10.0.0.5/32"
            warnFullTunnel={false}
          />
        </Field>

        <Field
          label="Client routed networks (in exported .conf)"
          hint="Affects the [Peer] AllowedIPs line in the .conf the peer installs. These are the networks the client will route THROUGH the tunnel. Server-side changes above do NOT update this list automatically — use the helper below if you want them in sync."
        >
          <CidrList
            ref={clientAllowedRef}
            value={clientAllowedIPs}
            onChange={setClientAllowedIPs}
            placeholder="10.10.0.0/24"
          />
          <button
            type="button"
            onClick={() => {
              // Pull the current server-side value (flush in case
              // the operator typed something but didn't commit) and
              // mirror it into the client side. Then we deduplicate
              // against whatever's already in client so a re-click
              // doesn't keep appending.
              const fromServer =
                allowedRef.current?.flush() ?? allowedIPs;
              const merged = Array.from(
                new Set([...clientAllowedIPs, ...fromServer]),
              );
              setClientAllowedIPs(merged);
            }}
            className="btn-ghost mt-2"
          >
            + Copy server-side routes here
          </button>
        </Field>

        <Field
          label="Endpoint override"
          hint={
            ownIface?.endpoint
              ? `Leave blank to use the location's endpoint: ${ownIface.endpoint}`
              : "Leave blank to inherit from the location."
          }
        >
          <input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="vpn.example.com:51820"
            className="field-input"
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

        <label className="flex items-center gap-2 text-sm text-muted">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          Enabled
        </label>

        <ConfigPreview
          assignedIP={peer.assigned_ip}
          interfaceCIDR={ownIface?.address}
          clientAllowedIPs={clientAllowedIPs}
          endpointOverride={endpoint}
          locationEndpoint={ownIface?.endpoint ?? null}
        />

        {mut.isError && (
          <p className="text-danger text-sm">
            {(mut.error as Error).message}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending}
            className="btn-primary"
          >
            {mut.isPending ? "Saving…" : "Save"}
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
