import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";

import { Modal } from "../components/Modal";
import { ApiError, api, type PageEnvelope } from "../lib/api";
import { useAuth } from "../lib/auth";

// The admin user list already carries totp_enabled per user. We reuse
// that endpoint to find the current user's flag rather than adding a
// dedicated /auth/whoami call — the list is small and the cache is
// shared with UsersPage.
interface UserRow {
  id: string;
  email: string;
  totp_enabled: boolean;
}

interface EnrollResponse {
  secret: string;
  otpauth_uri: string;
  account_name: string;
}

export function SecurityPage() {
  const { email } = useAuth();
  const qc = useQueryClient();
  const [enrollData, setEnrollData] = useState<EnrollResponse | null>(null);
  const [showDisable, setShowDisable] = useState(false);

  const { data: users } = useQuery({
    queryKey: ["users"],
    queryFn: () => api<PageEnvelope<UserRow>>("/api/v1/users?limit=100"),
  });
  // Match by email — the principal's user_id isn't on the auth ctx
  // today, and adding a /me endpoint just for this screen would be
  // scope creep.
  const me = users?.items.find(
    (u) => u.email.toLowerCase() === email?.toLowerCase(),
  );
  const totpEnabled = me?.totp_enabled ?? false;

  const startEnroll = useMutation<EnrollResponse, ApiError>({
    mutationFn: () =>
      api<EnrollResponse>("/api/v1/auth/totp/enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }),
    onSuccess: (data) => setEnrollData(data),
  });

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <header>
        <h1 className="text-xl font-semibold">Security</h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Manage two-factor authentication for your account.
        </p>
      </header>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-medium">Two-factor authentication</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {totpEnabled
                ? "Your account requires a 6-digit code at sign-in."
                : "Protect your account with a time-based one-time password."}
            </p>
          </div>
          {totpEnabled ? (
            <span className="inline-flex px-2 py-0.5 rounded-full bg-emerald-900/40 text-emerald-400 text-xs">
              enabled
            </span>
          ) : (
            <span className="inline-flex px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-xs">
              disabled
            </span>
          )}
        </div>

        {totpEnabled ? (
          <button
            onClick={() => setShowDisable(true)}
            className="px-3 py-1.5 rounded-md text-sm bg-rose-900/40 text-rose-300 hover:bg-rose-900/60 focus-visible:outline-2 focus-visible:outline-rose-400 focus-visible:outline-offset-2"
          >
            Disable 2FA
          </button>
        ) : (
          <button
            onClick={() => startEnroll.mutate()}
            disabled={startEnroll.isPending}
            className="px-3 py-1.5 rounded-md text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-indigo-400 focus-visible:outline-offset-2"
          >
            {startEnroll.isPending ? "Starting…" : "Enable 2FA"}
          </button>
        )}

        {startEnroll.isError && (
          <p className="text-sm text-rose-400">
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
    </div>
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
        headers: { "Content-Type": "application/json" },
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
      <ol className="list-decimal list-inside text-sm text-slate-300 space-y-2">
        <li>
          Scan the QR code (or enter the secret) in your authenticator app.
        </li>
        <li>Enter the 6-digit code the app displays to confirm.</li>
      </ol>

      <div className="flex flex-col items-center gap-3 py-2">
        <div className="bg-white p-3 rounded-md">
          <QRCodeSVG value={data.otpauth_uri} size={180} />
        </div>
        <div className="text-center">
          <p className="text-xs text-slate-500">
            Or enter this secret manually:
          </p>
          <code className="text-xs font-mono text-slate-300 break-all">
            {data.secret}
          </code>
        </div>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          verify.mutate();
        }}
        className="space-y-3"
      >
        <label htmlFor="enroll-code" className="block text-xs text-slate-400">
          Authenticator code
        </label>
        <input
          id="enroll-code"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="\d{6}"
          maxLength={6}
          required
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          className="w-full px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 text-lg tracking-[0.5em] text-center font-mono focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-1 focus:border-indigo-500"
        />
        {verify.isError && (
          <p className="text-sm text-rose-400">
            {(verify.error as ApiError).code === "TOTP_INVALID"
              ? "Code incorrect — try again."
              : (verify.error as Error).message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-md text-sm text-slate-300 hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={verify.isPending || code.length !== 6}
            className="px-4 py-2 rounded-md text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-indigo-400 focus-visible:outline-offset-2"
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
        headers: { "Content-Type": "application/json" },
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
        <div>
          <label
            htmlFor="disable-pw"
            className="block text-xs text-slate-400 mb-1"
          >
            Password
          </label>
          <input
            id="disable-pw"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 text-sm focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-1 focus:border-indigo-500"
          />
        </div>
        <div>
          <label
            htmlFor="disable-code"
            className="block text-xs text-slate-400 mb-1"
          >
            Authenticator code
          </label>
          <input
            id="disable-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="\d{6}"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            className="w-full px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 text-lg tracking-[0.5em] text-center font-mono focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-1 focus:border-indigo-500"
          />
        </div>
        {disable.isError && (
          <p className="text-sm text-rose-400">
            {(disable.error as Error).message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-md text-sm text-slate-300 hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-indigo-500 focus-visible:outline-offset-2"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={disable.isPending || !password || code.length !== 6}
            className="px-4 py-2 rounded-md text-sm bg-rose-700 hover:bg-rose-600 disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-rose-400 focus-visible:outline-offset-2"
          >
            {disable.isPending ? "Disabling…" : "Disable"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
