import { useState, useRef, useEffect } from "react";
import type { FormEvent } from "react";

import { Logo } from "../components/Logo";
import { ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";

export function LoginPage() {
  const { signIn } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  // needsTOTP drives the two-step UX: the first submit posts email
  // +password; if the server answers TOTP_REQUIRED we surface the
  // code field, retain the entered credentials (in state only), and
  // let the user retry with the 6-digit code without re-typing.
  const [needsTOTP, setNeedsTOTP] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (needsTOTP) totpRef.current?.focus();
  }, [needsTOTP]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await signIn(email, password, needsTOTP ? totpCode : undefined);
    } catch (ex) {
      if (ex instanceof ApiError) {
        if (ex.code === "TOTP_REQUIRED") {
          // Promote to the second step. Keep email/password in state
          // so the next submit includes them automatically.
          setNeedsTOTP(true);
          setErr(null);
        } else if (ex.code === "TOTP_INVALID") {
          setErr("Invalid authenticator code.");
          setTotpCode("");
        } else if (ex.code === "INVALID_CREDENTIALS") {
          setErr("Invalid email or password.");
          // If we were in the TOTP step, bail back to step one so
          // the user can correct whichever piece is actually wrong.
          setNeedsTOTP(false);
          setTotpCode("");
        } else {
          setErr(ex.message);
        }
      } else {
        setErr("Sign-in failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <form onSubmit={onSubmit} className="panel w-full max-w-sm space-y-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Logo size={36} />
            <h1 className="text-2xl font-bold text-white">NexusHub</h1>
          </div>
          <p className="text-muted text-sm mt-2">
            {needsTOTP
              ? "Enter the 6-digit code from your authenticator app."
              : "Sign in to continue."}
          </p>
        </div>

        {!needsTOTP && (
          <>
            <label className="field-label">
              <span className="field-label-text">Email</span>
              <input
                id="email"
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="field-input"
              />
            </label>
            <label className="field-label">
              <span className="field-label-text">Password</span>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="field-input"
              />
            </label>
          </>
        )}

        {needsTOTP && (
          <label className="field-label">
            <span className="field-label-text">Authenticator code</span>
            <input
              id="totp"
              ref={totpRef}
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="\d{6}"
              maxLength={6}
              required
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
              className="field-input text-center text-lg tracking-[0.5em] font-mono"
            />
            <button
              type="button"
              onClick={() => {
                setNeedsTOTP(false);
                setTotpCode("");
                setErr(null);
              }}
              className="text-faint hover:text-muted text-xs mt-2"
            >
              ← Use a different account
            </button>
          </label>
        )}

        {err && <p className="text-danger text-sm">{err}</p>}

        <button
          type="submit"
          disabled={busy || (needsTOTP && totpCode.length !== 6)}
          className="btn-primary w-full"
        >
          {busy ? "Signing in…" : needsTOTP ? "Verify" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
