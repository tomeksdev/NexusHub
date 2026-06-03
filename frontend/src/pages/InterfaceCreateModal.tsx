import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { ApiError, api } from "../lib/api";

interface Props {
  onClose: () => void;
  onCreated: (iface: { id: string; name: string }) => void;
}

interface CreatePayload {
  name: string;
  listen_port: number;
  address: string;
  dns?: string[];
  mtu?: number;
  endpoint?: string;
  post_up?: string;
  post_down?: string;
}

interface InterfaceResponse {
  id: string;
  name: string;
}

export function InterfaceCreateModal({ onClose, onCreated }: Props) {
  const qc = useQueryClient();
  const [name, setName] = useState("wg0");
  const [listenPort, setListenPort] = useState("51820");
  const [address, setAddress] = useState("");
  const [dns, setDns] = useState("");
  const [mtu, setMtu] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [postUp, setPostUp] = useState("");
  const [postDown, setPostDown] = useState("");

  const mut = useMutation<InterfaceResponse, ApiError>({
    mutationFn: () => {
      const port = parseInt(listenPort, 10);
      const body: CreatePayload = {
        name: name.trim(),
        listen_port: port,
        address: address.trim(),
      };
      const dnsList = dns
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (dnsList.length > 0) body.dns = dnsList;
      const mtuNum = parseInt(mtu, 10);
      if (!Number.isNaN(mtuNum) && mtuNum > 0) body.mtu = mtuNum;
      if (endpoint.trim()) body.endpoint = endpoint.trim();
      if (postUp.trim()) body.post_up = postUp.trim();
      if (postDown.trim()) body.post_down = postDown.trim();
      return api<InterfaceResponse>("/api/v1/interfaces", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: (iface) => {
      qc.invalidateQueries({ queryKey: ["interfaces"] });
      qc.invalidateQueries({ queryKey: ["wg-status"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      onCreated(iface);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !address.trim()) return;
    const port = parseInt(listenPort, 10);
    if (Number.isNaN(port) || port < 1 || port > 65535) return;
    mut.mutate();
  }

  return (
    <Modal title="New location" onClose={onClose} maxWidthClass="max-w-lg">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="wg0"
              className="field-input"
              autoFocus
              required
            />
          </Field>
          <Field label="Listen port" required>
            <input
              value={listenPort}
              onChange={(e) => setListenPort(e.target.value)}
              placeholder="51820"
              inputMode="numeric"
              className="field-input"
              required
            />
          </Field>
        </div>
        <Field
          label="Address (CIDR)"
          hint="The interface's own address inside the tunnel network."
          required
        >
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="10.7.0.1/24"
            className="field-input"
            required
          />
        </Field>
        <Field
          label="DNS"
          hint="Comma-separated. Pushed to peers that don't override it."
        >
          <input
            value={dns}
            onChange={(e) => setDns(e.target.value)}
            placeholder="1.1.1.1, 9.9.9.9"
            className="field-input"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="MTU">
            <input
              value={mtu}
              onChange={(e) => setMtu(e.target.value)}
              placeholder="default"
              inputMode="numeric"
              className="field-input"
            />
          </Field>
          <Field
            label="Endpoint"
            hint="Public host:port for exported peer configs."
          >
            <input
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="vpn.example.com:51820"
              className="field-input"
            />
          </Field>
        </div>
        <Field
          label="PostUp"
          hint="Optional. Shell command run after the interface comes up."
        >
          <input
            value={postUp}
            onChange={(e) => setPostUp(e.target.value)}
            placeholder="iptables -A FORWARD -i %i -j ACCEPT"
            className="field-input"
          />
        </Field>
        <Field label="PostDown">
          <input
            value={postDown}
            onChange={(e) => setPostDown(e.target.value)}
            placeholder="iptables -D FORWARD -i %i -j ACCEPT"
            className="field-input"
          />
        </Field>

        {mut.isError && (
          <p className="text-danger text-sm">
            {mut.error instanceof ApiError
              ? mut.error.message
              : "Failed to create location"}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || !name.trim() || !address.trim()}
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
