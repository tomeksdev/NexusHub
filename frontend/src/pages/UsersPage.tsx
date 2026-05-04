import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { useNowEveryMinute } from "../lib/hooks";
import { UserCreateModal } from "./UserCreateModal";
import { UserEditModal, type EditableUser } from "./UserEditModal";

interface User {
  id: string;
  email: string;
  username: string;
  role: "super_admin" | "admin" | "user";
  is_active: boolean;
  totp_enabled: boolean;
  last_login_at?: string | null;
  failed_logins: number;
  locked_until?: string | null;
  created_at: string;
}

interface Props {
  // Called when the operator clicks a user row. Drives the App
  // shell's drill-down into UserDetailPage.
  onOpen?: (userID: string) => void;
}

export function UsersPage({ onOpen }: Props = {}) {
  const qc = useQueryClient();
  const nowMs = useNowEveryMinute();
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState<EditableUser | null>(null);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["users"],
    queryFn: () => api<PageEnvelope<User>>("/api/v1/users?limit=100"),
  });

  const deleteMut = useMutation({
    mutationFn: ({ id, force }: { id: string; force: boolean }) =>
      api(
        `/api/v1/users/${id}${force ? "?force=true" : ""}`,
        { method: "DELETE" },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });

  if (isLoading) return <div className="p-6 text-muted">Loading…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const items = data?.items ?? [];

  function onDelete(u: User) {
    // Two confirms: first soft-disable, then optional hard delete via
    // a follow-up — easier to communicate than a single flag the
    // operator might miss.
    if (u.is_active) {
      if (!confirm(`Disable user "${u.email}"? They won't be able to log in.`))
        return;
      deleteMut.mutate({ id: u.id, force: false });
      return;
    }
    if (
      confirm(
        `User "${u.email}" is already disabled. Permanently delete? This unlinks their peers (peers stay; their owner is cleared).`,
      )
    ) {
      deleteMut.mutate({ id: u.id, force: true });
    }
  }

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Users</h1>
        <div className="topbar-actions">
          <span className="text-muted text-sm">{data?.total ?? 0} total</span>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn-primary"
          >
            + New user
          </button>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="panel">
          <p className="text-muted">No users yet.</p>
        </div>
      ) : (
        <div className="data-table">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th>2FA</th>
                <th>Last login</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                const locked =
                  !!u.locked_until &&
                  new Date(u.locked_until).getTime() > nowMs;
                return (
                  <tr
                    key={u.id}
                    onClick={onOpen ? () => onOpen(u.id) : undefined}
                    style={onOpen ? { cursor: "pointer" } : undefined}
                  >
                    <td className="font-medium">{u.email}</td>
                    <td className="text-muted">{u.username}</td>
                    <td>
                      <span className={roleBadge(u.role)}>{u.role}</span>
                    </td>
                    <td>
                      {!u.is_active ? (
                        <span className="status-badge muted">
                          <span className="dot" />
                          DISABLED
                        </span>
                      ) : locked ? (
                        <span className="status-badge critical">
                          <span className="dot" />
                          LOCKED
                        </span>
                      ) : (
                        <span className="status-badge ok">
                          <span className="dot" />
                          ACTIVE
                        </span>
                      )}
                    </td>
                    <td className="text-muted">
                      {u.totp_enabled ? "TOTP" : <span className="text-faint">off</span>}
                    </td>
                    <td className="text-muted">
                      {u.last_login_at
                        ? new Date(u.last_login_at).toLocaleString()
                        : "—"}
                    </td>
                    <td className="text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="inline-flex gap-2">
                        <button
                          type="button"
                          onClick={() => setEditTarget(u)}
                          className="btn-ghost"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => onDelete(u)}
                          disabled={deleteMut.isPending}
                          className="btn-danger"
                        >
                          {u.is_active ? "Disable" : "Delete"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <UserCreateModal
          onClose={() => setShowCreate(false)}
          onCreated={() => setShowCreate(false)}
        />
      )}
      {editTarget && (
        <UserEditModal
          user={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={() => setEditTarget(null)}
        />
      )}
    </div>
  );
}

function roleBadge(role: string): string {
  const base = "inline-flex px-2 py-0.5 rounded-full text-xs font-semibold ";
  if (role === "super_admin")
    return base + "bg-[#FF4C4C]/20 text-[#FF4C4C]";
  if (role === "admin") return base + "bg-indigo-500/20 text-indigo-300";
  return base + "bg-white/10 text-muted";
}
