import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { ApiError, api } from "../lib/api";

interface IfaceLite {
  id: string;
  name: string;
  listen_port: number;
  address: string;
  dns: string[];
  mtu?: number | null;
  endpoint?: string | null;
  post_up?: string | null;
  post_down?: string | null;
  public_key: string;
}

interface Props {
  iface: IfaceLite;
  onClose: () => void;
  onSaved: () => void;
}

interface PatchPayload {
  listen_port?: number;
  address?: string;
  dns?: string[];
  mtu?: number | null;
  endpoint?: string | null;
  post_up?: string | null;
  post_down?: string | null;
}

export function InterfaceEditModal({ iface, onClose, onSaved }: Props) {
  const [listenPort, setListenPort] = useState(String(iface.listen_port));
  const [address, setAddress] = useState(iface.address);
  const [dns, setDns] = useState(iface.dns.join(", "));
  const [mtu, setMtu] = useState(iface.mtu != null ? String(iface.mtu) : "");
  const [endpoint, setEndpoint] = useState(iface.endpoint ?? "");
  const [postUp, setPostUp] = useState(iface.post_up ?? "");
  const [postDown, setPostDown] = useState(iface.post_down ?? "");

  const mut = useMutation<unknown, ApiError>({
    mutationFn: () => {
      const body: PatchPayload = {};
      const port = parseInt(listenPort, 10);
      if (!Number.isNaN(port) && port !== iface.listen_port)
        body.listen_port = port;
      if (address.trim() !== iface.address) body.address = address.trim();
      const dnsList = dns
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const sameDns =
        dnsList.length === iface.dns.length &&
        dnsList.every((v, i) => v === iface.dns[i]);
      if (!sameDns) body.dns = dnsList;
      const mtuNum = parseInt(mtu, 10);
      const targetMtu = Number.isNaN(mtuNum) ? null : mtuNum;
      if (targetMtu !== (iface.mtu ?? null)) body.mtu = targetMtu;
      const targetEndpoint = endpoint.trim() === "" ? null : endpoint.trim();
      if (targetEndpoint !== (iface.endpoint ?? null))
        body.endpoint = targetEndpoint;
      const targetPostUp = postUp.trim() === "" ? null : postUp.trim();
      if (targetPostUp !== (iface.post_up ?? null)) body.post_up = targetPostUp;
      const targetPostDown = postDown.trim() === "" ? null : postDown.trim();
      if (targetPostDown !== (iface.post_down ?? null))
        body.post_down = targetPostDown;
      return api(`/api/v1/interfaces/${iface.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
    },
    onSuccess: onSaved,
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    mut.mutate();
  }

  return (
    <Modal
      title={`Edit ${iface.name}`}
      description="Name and key material are not editable."
      onClose={onClose}
      maxWidthClass="max-w-lg"
    >
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name (read-only)">
            <input
              value={iface.name}
              readOnly
              className="field-input opacity-60 cursor-not-allowed"
            />
          </Field>
          <Field label="Listen port">
            <input
              value={listenPort}
              onChange={(e) => setListenPort(e.target.value)}
              inputMode="numeric"
              className="field-input"
            />
          </Field>
        </div>
        <Field label="Address (CIDR)">
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="field-input"
          />
        </Field>
        <Field label="DNS" hint="Comma-separated.">
          <input
            value={dns}
            onChange={(e) => setDns(e.target.value)}
            className="field-input"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="MTU">
            <input
              value={mtu}
              onChange={(e) => setMtu(e.target.value)}
              inputMode="numeric"
              className="field-input"
            />
          </Field>
          <Field label="Endpoint">
            <input
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <Field label="PostUp">
          <input
            value={postUp}
            onChange={(e) => setPostUp(e.target.value)}
            className="field-input"
          />
        </Field>
        <Field label="PostDown">
          <input
            value={postDown}
            onChange={(e) => setPostDown(e.target.value)}
            className="field-input"
          />
        </Field>
        <Field label="Public key">
          <input
            value={iface.public_key}
            readOnly
            className="field-input opacity-60 cursor-not-allowed font-mono text-xs"
          />
        </Field>

        {mut.isError && (
          <p className="text-danger text-sm">
            {mut.error instanceof ApiError
              ? mut.error.message
              : "Failed to save"}
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
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field-label">
      <span className="field-label-text">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}
