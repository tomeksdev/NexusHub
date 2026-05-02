import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";

import { Modal } from "../components/Modal";
import { ApiError, api, type PageEnvelope } from "../lib/api";
import { useAuth } from "../lib/auth";

interface UserRow {
  id: string;
  email: string;
  username: string;
  role: string;
  totp_enabled: boolean;
}

interface EnrollResponse {
  secret: string;
  otpauth_uri: string;
  account_name: string;
}

export function ProfilePage() {
  const { email, role } = useAuth();
  const qc = useQueryClient();
  const [enrollData, setEnrollData] = useState<EnrollResponse | null>(null);
  const [showDisable, setShowDisable] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);

  const { data: users } = useQuery({
    queryKey: ["users"],
    queryFn: () => api<PageEnvelope<UserRow>>("/api/v1/users?limit=100"),
    // Non-admins don't get this list; the catch falls back to "no row"
    // which means the profile section just renders the auth-context
    // values without the totp flag. We avoid throwing.
    retry: false,
  });
  const me = users?.items.find(
    (u) => u.email.toLowerCase() === email?.toLowerCase(),
  );
  const totpEnabled = me?.totp_enabled ?? false;

  const startEnroll = useMutation<EnrollResponse, ApiError>({
    mutationFn: () =>
      api<EnrollResponse>("/api/v1/auth/totp/enroll", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    onSuccess: (data) => setEnrollData(data),
  });

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="topbar">
        <h1 className="page-title">My Profile</h1>
      </div>

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">Account</span>
        </div>
        <dl className="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
          <dt className="text-muted">Email</dt>
          <dd>{email ?? "—"}</dd>
          <dt className="text-muted">Username</dt>
          <dd>{me?.username ?? "—"}</dd>
          <dt className="text-muted">Role</dt>
          <dd className="font-mono text-faint">{role ?? "—"}</dd>
        </dl>
        <div className="mt-4">
          <button
            type="button"
            onClick={() => setShowPasswordModal(true)}
            className="btn-ghost"
          >
            Change password
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Two-factor authentication</div>
            <p className="text-muted text-xs mt-1">
              {totpEnabled
                ? "Your account requires a 6-digit code at sign-in."
                : "Protect your account with a time-based one-time password."}
            </p>
          </div>
          {totpEnabled ? (
            <span className="status-badge ok">
              <span className="dot" />
              ENABLED
            </span>
          ) : (
            <span className="status-badge muted">
              <span className="dot" />
              DISABLED
            </span>
          )}
        </div>
        {totpEnabled ? (
          <button
            type="button"
            onClick={() => setShowDisable(true)}
            className="btn-danger"
          >
            Disable 2FA
          </button>
        ) : (
          <button
            type="button"
            onClick={() => startEnroll.mutate()}
            disabled={startEnroll.isPending}
            className="btn-primary"
          >
            {startEnroll.isPending ? "Starting…" : "Enable 2FA"}
          </button>
        )}
        {startEnroll.isError && (
          <p className="text-danger text-sm mt-3">
            {(startEnroll.error as Error).message}
          </p>
        )}
      </section>

      {enrollData && (
        <EnrollModal
          data={enrollData}
          onClose={() => setEnrollData(null)}
          onVerified={() => {
            setEnrollData(null);
            qc.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}
      {showDisable && (
        <DisableModal
          onClose={() => setShowDisable(false)}
          onDisabled={() => {
            setShowDisable(false);
            qc.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}
      {showPasswordModal && (
        <PasswordChangeModal onClose={() => setShowPasswordModal(false)} />
      )}
    </div>
  );
}

function PasswordChangeModal({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const mut = useMutation<void, ApiError>({
    mutationFn: () =>
      api("/api/v1/auth/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: current,
          new_password: next,
        }),
      }).then(() => undefined),
    onSuccess: onClose,
  });
  const mismatch = next.length > 0 && confirm.length > 0 && next !== confirm;

  return (
    <Modal title="Change password" onClose={onClose} maxWidthClass="max-w-md">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (mismatch || !current || !next) return;
          mut.mutate();
        }}
        className="space-y-3"
      >
        <label className="field-label">
          <span className="field-label-text">Current password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className="field-input"
          />
        </label>
        <label className="field-label">
          <span className="field-label-text">New password</span>
          <input
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            className="field-input"
          />
          <span className="field-hint">12+ characters required.</span>
        </label>
        <label className="field-label">
          <span className="field-label-text">Confirm new password</span>
          <input
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="field-input"
          />
          {mismatch && (
            <span className="field-hint text-danger">
              Passwords don't match.
            </span>
          )}
        </label>
        {mut.isError && (
          <p className="text-danger text-sm">{(mut.error as Error).message}</p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending || mismatch || !current || !next}
            className="btn-primary"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EnrollModal({
  data,
  onClose,
  onVerified,
}: {
  data: EnrollResponse;
  onClose: () => void;
  onVerified: () => void;
}) {
  const [code, setCode] = useState("");
  const verify = useMutation<void, ApiError>({
    mutationFn: () =>
      api("/api/v1/auth/totp/verify", {
        method: "POST",
        body: JSON.stringify({ code }),
      }).then(() => undefined),
    onSuccess: onVerified,
  });

  return (
    <Modal
      title="Set up 2FA"
      description={`Account: ${data.account_name}`}
      onClose={onClose}
      maxWidthClass="max-w-lg"
    >
      <ol className="list-decimal list-inside text-sm space-y-2">
        <li>Scan the QR code (or enter the secret) in your authenticator.</li>
        <li>Enter the 6-digit code the app displays to confirm.</li>
      </ol>
      <div className="flex flex-col items-center gap-3 py-2">
        <div className="bg-white p-3 rounded-md">
          <QRCodeSVG value={data.otpauth_uri} size={180} />
        </div>
        <div className="text-center">
          <p className="text-faint text-xs">Or enter this secret manually:</p>
          <code className="text-xs font-mono break-all">{data.secret}</code>
        </div>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          verify.mutate();
        }}
        className="space-y-3"
      >
        <label className="field-label">
          <span className="field-label-text">Authenticator code</span>
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="\d{6}"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            className="field-input text-center text-lg tracking-[0.5em] font-mono"
          />
        </label>
        {verify.isError && (
          <p className="text-danger text-sm">
            {(verify.error as ApiError).code === "TOTP_INVALID"
              ? "Code incorrect — try again."
              : (verify.error as Error).message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={verify.isPending || code.length !== 6}
            className="btn-primary"
          >
            {verify.isPending ? "Verifying…" : "Enable"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DisableModal({
  onClose,
  onDisabled,
}: {
  onClose: () => void;
  onDisabled: () => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const disable = useMutation<void, ApiError>({
    mutationFn: () =>
      api("/api/v1/auth/totp/disable", {
        method: "POST",
        body: JSON.stringify({ password, code }),
      }).then(() => undefined),
    onSuccess: onDisabled,
  });

  return (
    <Modal
      title="Disable 2FA"
      description="Enter your password and a current 6-digit code to confirm."
      onClose={onClose}
      maxWidthClass="max-w-md"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          disable.mutate();
        }}
        className="space-y-3"
      >
        <label className="field-label">
          <span className="field-label-text">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="field-input"
          />
        </label>
        <label className="field-label">
          <span className="field-label-text">Authenticator code</span>
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="\d{6}"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            className="field-input text-center text-lg tracking-[0.5em] font-mono"
          />
        </label>
        {disable.isError && (
          <p className="text-danger text-sm">
            {(disable.error as Error).message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button
            type="submit"
            disabled={disable.isPending || !password || code.length !== 6}
            className="btn-danger"
          >
            {disable.isPending ? "Disabling…" : "Disable"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
