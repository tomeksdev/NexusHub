import { useState, type FormEvent } from "react";
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
    <Modal title="New interface" onClose={onClose} maxWidthClass="max-w-lg">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="wg0"
              className={inputCls}
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
              className={inputCls}
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
            className={inputCls}
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
            className={inputCls}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="MTU">
            <input
              value={mtu}
              onChange={(e) => setMtu(e.target.value)}
              placeholder="default"
              inputMode="numeric"
              className={inputCls}
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
              className={inputCls}
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
            className={inputCls}
          />
        </Field>
        <Field label="PostDown">
          <input
            value={postDown}
            onChange={(e) => setPostDown(e.target.value)}
            placeholder="iptables -D FORWARD -i %i -j ACCEPT"
            className={inputCls}
          />
        </Field>

        {mut.isError && (
          <p className="text-rose-400 text-sm">
            {mut.error instanceof ApiError
              ? mut.error.message
              : "Failed to create interface"}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-md text-slate-300 hover:bg-slate-800 text-sm focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || !name.trim() || !address.trim()}
            className="px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:hover:bg-sky-600 text-sm font-medium focus-visible:outline-2 focus-visible:outline-sky-400 focus-visible:outline-offset-2"
          >
            {mut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const inputCls =
  "w-full rounded-md bg-slate-800 border border-slate-700 px-2 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-1 focus:border-sky-500";

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
    <label className="block">
      <span className="text-xs text-slate-400 mb-1 inline-block">
        {label}
        {required && <span className="text-rose-400 ml-0.5">*</span>}
      </span>
      {children}
      {hint && (
        <span className="text-xs text-slate-500 block mt-1">{hint}</span>
      )}
    </label>
  );
}
