// Minimal fetch-based API client. All requests go through `api()` so the
// 401 → refresh retry lives in exactly one place. Access tokens stay in
// memory; refresh tokens persist in localStorage so a page reload keeps
// the session. If an XSS ever lands on this app an attacker can exfiltrate
// the refresh token from storage — that's a known trade against the UX
// cost of re-login on every page load. When we add a service worker we
// can move the refresh token into an HTTP-only cookie.

export interface ApiErrorBody {
  error: string;
  code: string;
}

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, body: ApiErrorBody) {
    super(body.error);
    this.status = status;
    this.code = body.code;
  }
}

export interface PageEnvelope<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  sort?: string;
}

const REFRESH_KEY = "nexushub.refresh";

let accessToken: string | null = null;
let accessExpiresAt: number = 0; // epoch ms
let onAuthCleared: (() => void) | null = null;

export function setTokens(
  access: string,
  accessExpires: string,
  refresh?: string,
) {
  accessToken = access;
  accessExpiresAt = new Date(accessExpires).getTime();
  if (refresh !== undefined) {
    localStorage.setItem(REFRESH_KEY, refresh);
  }
}

export function clearTokens() {
  accessToken = null;
  accessExpiresAt = 0;
  localStorage.removeItem(REFRESH_KEY);
  if (onAuthCleared) onAuthCleared();
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function onAuthLost(cb: () => void) {
  onAuthCleared = cb;
}

export function hasSession(): boolean {
  return !!getRefreshToken() || !!accessToken;
}

// getAccessTokenForStream returns a fresh access token for callers (SSE,
// WebSocket) that open long-lived connections and can't retry on 401 the
// way api() does. Triggers the same pre-expiry refresh as api().
export async function getAccessTokenForStream(): Promise<string | null> {
  if (!accessToken || Date.now() > accessExpiresAt - 30_000) {
    if (getRefreshToken()) await refresh();
  }
  return accessToken;
}

// refresh swaps the saved refresh token for a new access + refresh pair.
// We await this from api() when the access token is missing or expired.
async function refresh(): Promise<void> {
  const rt = getRefreshToken();
  if (!rt)
    throw new ApiError(401, {
      error: "no refresh token",
      code: "UNAUTHORIZED",
    });

  const resp = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: rt }),
  });
  if (!resp.ok) {
    clearTokens();
    const body = await resp
      .json()
      .catch(() => ({ error: "refresh failed", code: "UNAUTHORIZED" }));
    throw new ApiError(resp.status, body);
  }
  const data: {
    access_token: string;
    access_expires_at: string;
    refresh_token: string;
  } = await resp.json();
  setTokens(data.access_token, data.access_expires_at, data.refresh_token);
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  // Refresh proactively if the access token is within 30s of expiry. Saves
  // a round-trip compared to waiting for the 401.
  if (!accessToken || Date.now() > accessExpiresAt - 30_000) {
    if (getRefreshToken()) {
      await refresh();
    }
  }

  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(path, { ...init, headers });

  // Race: another tab rotated our refresh token between the expiry check
  // and the actual request, so the API rejects our (now stale) access
  // token. Retry once.
  if (resp.status === 401 && getRefreshToken()) {
    try {
      await refresh();
      headers.set("Authorization", `Bearer ${accessToken}`);
      const retry = await fetch(path, { ...init, headers });
      return handleResp<T>(retry);
    } catch {
      clearTokens();
      throw new ApiError(401, {
        error: "session expired",
        code: "UNAUTHORIZED",
      });
    }
  }

  return handleResp<T>(resp);
}

async function handleResp<T>(resp: Response): Promise<T> {
  if (resp.status === 204) return undefined as T;
  const text = await resp.text();
  const body = text ? JSON.parse(text) : undefined;
  if (!resp.ok) {
    throw new ApiError(resp.status, body as ApiErrorBody);
  }
  return body as T;
}

// apiText + apiBlob exist because the JSON-first api() helper would try
// to JSON.parse a .conf file or a PNG. Same auth + refresh flow, just a
// different body-reader at the end. The refresh flow is replicated
// rather than shared because the generic over-response-body split is
// more work than two short functions.
export async function apiText(
  path: string,
  init: RequestInit = {},
): Promise<string> {
  const resp = await authedFetch(path, init);
  if (!resp.ok) {
    const body = await resp
      .json()
      .catch(() => ({ error: resp.statusText, code: "UNAUTHORIZED" }));
    throw new ApiError(resp.status, body as ApiErrorBody);
  }
  return resp.text();
}

export async function apiBlob(
  path: string,
  init: RequestInit = {},
): Promise<Blob> {
  const resp = await authedFetch(path, init);
  if (!resp.ok) {
    const body = await resp
      .json()
      .catch(() => ({ error: resp.statusText, code: "UNAUTHORIZED" }));
    throw new ApiError(resp.status, body as ApiErrorBody);
  }
  return resp.blob();
}

// authedFetch is the shared request builder used by apiText/apiBlob. It
// replicates the access-token lifecycle from api() — pre-expiry refresh
// and a single 401 retry — without the JSON assumptions.
async function authedFetch(path: string, init: RequestInit): Promise<Response> {
  if (!accessToken || Date.now() > accessExpiresAt - 30_000) {
    if (getRefreshToken()) await refresh();
  }
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const resp = await fetch(path, { ...init, headers });
  if (resp.status !== 401 || !getRefreshToken()) return resp;

  try {
    await refresh();
    headers.set("Authorization", `Bearer ${accessToken}`);
    return await fetch(path, { ...init, headers });
  } catch {
    clearTokens();
    throw new ApiError(401, { error: "session expired", code: "UNAUTHORIZED" });
  }
}

// ---- Typed endpoint wrappers ----------------------------------------------

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  access_expires_at: string;
  role: string;
}

// login posts credentials to the backend. When totpCode is omitted
// and the user has 2FA enabled the server responds 401 with code
// TOTP_REQUIRED; callers catch that and collect the code for a
// retry. Same-signature retries with the code populated complete
// the flow.
export async function login(
  email: string,
  password: string,
  totpCode?: string,
): Promise<LoginResponse> {
  const body: Record<string, string> = { email, password };
  if (totpCode) body.totp_code = totpCode;
  const resp = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const errBody = await resp
      .json()
      .catch(() => ({ error: "login failed", code: "UNAUTHORIZED" }));
    throw new ApiError(resp.status, errBody);
  }
  const data: LoginResponse = await resp.json();
  setTokens(data.access_token, data.access_expires_at, data.refresh_token);
  return data;
}

export async function logout(): Promise<void> {
  const rt = getRefreshToken();
  if (rt) {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    }).catch(() => {
      // logout is best-effort — always clear local state even if the call failed
    });
  }
  clearTokens();
}
