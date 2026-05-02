import { useQuery } from "@tanstack/react-query";

import { api, type PageEnvelope } from "../lib/api";
import { useNowEveryMinute } from "../lib/hooks";

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

export function UsersPage() {
  const nowMs = useNowEveryMinute();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["users"],
    queryFn: () => api<PageEnvelope<User>>("/api/v1/users?limit=100"),
  });

  if (isLoading)
    return <div className="p-6 text-muted">Loading…</div>;
  if (isError)
    return (
      <div className="p-6 text-danger">
        Failed to load: {(error as Error).message}
      </div>
    );

  const items = data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="topbar">
        <h1 className="page-title">Users</h1>
        <span className="text-muted text-sm">
          {data?.total ?? 0} total
        </span>
      </div>
      {items.length === 0 ? (
        <p className="text-muted text-sm">No users yet.</p>
      ) : (
        <div className="data-table">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th>Email</th>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th>2FA</th>
                <th>Last login</th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                const locked =
                  !!u.locked_until &&
                  new Date(u.locked_until).getTime() > nowMs;
                return (
                  <tr key={u.id}>
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
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
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
