import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { ApiError, api } from "../lib/api";

interface Props {
  onClose: () => void;
  onCreated: (user: { id: string; email: string }) => void;
}

interface Payload {
  email: string;
  username: string;
  password: string;
  role: string;
}

interface UserResponse {
  id: string;
  email: string;
}

const ROLES = ["user", "admin", "super_admin"] as const;

export function UserCreateModal({ onClose, onCreated }: Props) {
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<string>("user");

  const mut = useMutation<UserResponse, ApiError>({
    mutationFn: () => {
      const body: Payload = {
        email: email.trim(),
        username: username.trim(),
        password,
        role,
      };
      return api<UserResponse>("/api/v1/users", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: (user) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      onCreated(user);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!email.trim() || !username.trim() || password.length < 12) return;
    mut.mutate();
  }

  return (
    <Modal title="New user" onClose={onClose} maxWidthClass="max-w-md">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email" required>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="alice@example.com"
            className="field-input"
            autoFocus
            required
          />
        </Field>
        <Field label="Username" required>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="alice"
            className="field-input"
            required
            minLength={2}
            maxLength={64}
          />
        </Field>
        <Field
          label="Password"
          hint="12+ characters. Share with the user out of band; there's no email yet."
          required
        >
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="field-input"
            required
            minLength={12}
          />
        </Field>
        <Field label="Role">
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="field-input"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Field>

        {mut.isError && (
          <p className="text-danger text-sm">
            {mut.error instanceof ApiError
              ? mut.error.message
              : "Failed to create user"}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={
              mut.isPending ||
              !email.trim() ||
              !username.trim() ||
              password.length < 12
            }
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
