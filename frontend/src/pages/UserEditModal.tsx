import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Modal } from "../components/Modal";
import { ApiError, api } from "../lib/api";

export interface EditableUser {
  id: string;
  email: string;
  username: string;
  role: "super_admin" | "admin" | "user";
  is_active: boolean;
}

interface Props {
  user: EditableUser;
  onClose: () => void;
  onSaved: () => void;
}

interface Payload {
  email?: string;
  username?: string;
  role?: string;
  is_active?: boolean;
}

const ROLES = ["user", "admin", "super_admin"] as const;

export function UserEditModal({ user, onClose, onSaved }: Props) {
  const qc = useQueryClient();
  const [email, setEmail] = useState(user.email);
  const [username, setUsername] = useState(user.username);
  const [role, setRole] = useState<string>(user.role);
  const [isActive, setIsActive] = useState(user.is_active);
  const [showPassword, setShowPassword] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  const update = useMutation<unknown, ApiError>({
    mutationFn: () => {
      const body: Payload = {};
      if (email.trim() !== user.email) body.email = email.trim();
      if (username.trim() !== user.username) body.username = username.trim();
      if (role !== user.role) body.role = role;
      if (isActive !== user.is_active) body.is_active = isActive;
      return api(`/api/v1/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      onSaved();
    },
  });

  const setPassword = useMutation<unknown, ApiError>({
    mutationFn: () =>
      api(`/api/v1/users/${user.id}/password`, {
        method: "POST",
        body: JSON.stringify({ password: newPassword }),
      }),
    onSuccess: () => {
      setNewPassword("");
      setShowPassword(false);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    update.mutate();
  }

  return (
    <Modal
      title={`Edit ${user.username}`}
      description={user.email}
      onClose={onClose}
      maxWidthClass="max-w-md"
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="field-input"
            required
          />
        </Field>
        <Field label="Username">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="field-input"
            required
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
        <label className="flex items-center gap-2 text-sm text-muted">
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e) => setIsActive(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          Active
        </label>

        {update.isError && (
          <p className="text-danger text-sm">
            {(update.error as Error).message}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={update.isPending}
            className="btn-primary"
          >
            {update.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>

      <div className="border-t border-[var(--color-line)] pt-4 mt-4">
        {!showPassword ? (
          <button
            type="button"
            onClick={() => setShowPassword(true)}
            className="btn-ghost"
          >
            Reset password
          </button>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (newPassword.length < 12) return;
              setPassword.mutate();
            }}
            className="space-y-3"
          >
            <Field
              label="New password"
              hint="12+ characters. Share out of band — the user won't be emailed."
            >
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="field-input"
                required
                minLength={12}
                autoFocus
              />
            </Field>
            {setPassword.isError && (
              <p className="text-danger text-sm">
                {(setPassword.error as Error).message}
              </p>
            )}
            {setPassword.isSuccess && (
              <p className="text-success text-sm">Password updated.</p>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowPassword(false);
                  setNewPassword("");
                }}
                className="btn-ghost"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={setPassword.isPending || newPassword.length < 12}
                className="btn-danger"
              >
                {setPassword.isPending ? "Saving…" : "Set password"}
              </button>
            </div>
          </form>
        )}
      </div>
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
