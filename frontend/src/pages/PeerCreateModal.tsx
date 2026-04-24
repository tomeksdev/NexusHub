import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { Modal } from '../components/Modal'
import { ApiError, api } from '../lib/api'

interface Props {
  interfaceID: string
  onClose: () => void
  onCreated: (peer: { id: string; name: string }) => void
}

interface CreatePayload {
  interface_id: string
  name: string
  description?: string
  assigned_ip?: string
  allowed_ips?: string[]
  endpoint?: string
  dns?: string[]
  persistent_keepalive?: number
}

interface PeerResponse {
  id: string
  name: string
}

export function PeerCreateModal({ interfaceID, onClose, onCreated }: Props) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [assignedIP, setAssignedIP] = useState('')
  const [allowedIPs, setAllowedIPs] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [keepalive, setKeepalive] = useState('')

  const mut = useMutation<PeerResponse, ApiError>({
    mutationFn: () => {
      const body: CreatePayload = { interface_id: interfaceID, name }
      if (description.trim()) body.description = description.trim()
      if (assignedIP.trim()) body.assigned_ip = assignedIP.trim()
      // allowed_ips is comma-separated in the UI; split + trim so the user
      // can paste "10.0.0.0/24, 10.1.0.0/16" without shape gymnastics.
      const ips = allowedIPs.split(',').map((s) => s.trim()).filter(Boolean)
      if (ips.length > 0) body.allowed_ips = ips
      if (endpoint.trim()) body.endpoint = endpoint.trim()
      const ka = parseInt(keepalive, 10)
      if (!Number.isNaN(ka) && ka > 0) body.persistent_keepalive = ka
      return api<PeerResponse>('/api/v1/peers', {
        method: 'POST',
        body: JSON.stringify(body),
      })
    },
    onSuccess: (peer) => {
      qc.invalidateQueries({ queryKey: ['peers'] })
      onCreated(peer)
    },
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    mut.mutate()
  }

  return (
    <Modal title="New peer" onClose={onClose} maxWidthClass="max-w-lg">
      <form onSubmit={submit} className="space-y-4">
          <Field label="Name" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="alice-laptop"
              className={inputCls}
              autoFocus
              required
            />
          </Field>
          <Field label="Description">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="optional"
              className={inputCls}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Assigned IP">
              <input
                value={assignedIP}
                onChange={(e) => setAssignedIP(e.target.value)}
                placeholder="auto-allocate"
                className={inputCls}
              />
            </Field>
            <Field label="Persistent keepalive (s)">
              <input
                value={keepalive}
                onChange={(e) => setKeepalive(e.target.value)}
                placeholder="e.g. 25"
                inputMode="numeric"
                className={inputCls}
              />
            </Field>
          </div>
          <Field label="Allowed IPs" hint="Comma-separated. Defaults to the assigned /32.">
            <input
              value={allowedIPs}
              onChange={(e) => setAllowedIPs(e.target.value)}
              placeholder="10.0.0.0/24, 10.1.0.0/16"
              className={inputCls}
            />
          </Field>
          <Field label="Endpoint" hint="Override the interface endpoint for this peer.">
            <input
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="vpn.example.com:51820"
              className={inputCls}
            />
          </Field>

          {mut.isError && (
            <p className="text-rose-400 text-sm">
              {mut.error instanceof ApiError ? mut.error.message : 'Failed to create peer'}
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
            disabled={mut.isPending || !name.trim()}
            className="px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:hover:bg-sky-600 text-sm font-medium focus-visible:outline-2 focus-visible:outline-sky-400 focus-visible:outline-offset-2"
          >
            {mut.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

const inputCls =
  'w-full rounded-md bg-slate-800 border border-slate-700 px-2 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-1 focus:border-sky-500'

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string
  hint?: string
  required?: boolean
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-xs text-slate-400 mb-1 inline-block">
        {label}
        {required && <span className="text-rose-400 ml-0.5">*</span>}
      </span>
      {children}
      {hint && <span className="text-xs text-slate-500 block mt-1">{hint}</span>}
    </label>
  )
}
