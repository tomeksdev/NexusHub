import { useQuery } from "@tanstack/react-query";

import { api } from "../lib/api";

interface Health {
  status: string;
  version?: string;
  commit?: string;
}

interface KernelWarning {
  occurred_at: string;
  origin: string;
  iface?: string;
  message: string;
}

interface KernelWarningsResp {
  items: KernelWarning[];
}

interface EBPFAttachment {
  iface: string;
  hook: string;
  program: string;
  prog_id: number;
}

// Array fields are typed as nullable because Go marshals a nil slice
// as JSON `null` — if the backend ever regresses on its empty-slice
// guarantee the page must still render. (#102)
interface EBPFLoaderStatus {
  loaded: boolean;
  error?: string | null;
  capabilities_ok: boolean;
  missing_features: string[] | null;
  permission_denied: boolean;
  last_attempt_at: string;
}

interface EBPFStateResp {
  programs: EBPFAttachment[] | null;
  pin_path?: string;
  loader: EBPFLoaderStatus;
}

export function SupportPage() {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => api<Health>("/api/v1/health"),
    retry: false,
    staleTime: 60_000,
  });

  // Pull recent kernel-apply warnings every 30 s. Admin-only — the
  // backend route is gated, and a non-admin user view of the Support
  // page won't even attempt this fetch (the catch handler swallows
  // the 403 quietly).
  const warningsQ = useQuery({
    queryKey: ["kernel-warnings"],
    queryFn: () => api<KernelWarningsResp>("/api/v1/diag/kernel-warnings"),
    retry: false,
    refetchInterval: 30_000,
  });
  const warnings = warningsQ.data?.items ?? [];

  // eBPF attachment inventory — surfaces what the API thinks is
  // bound to which iface, with the kernel program id so the
  // operator can correlate against `bpftool prog show` and
  // `bpftool net`. Round-9 observability for the "rules are
  // LOADED but is the program actually running" question.
  const ebpfQ = useQuery({
    queryKey: ["ebpf-state"],
    queryFn: () => api<EBPFStateResp>("/api/v1/diag/ebpf"),
    retry: false,
    refetchInterval: 30_000,
  });
  const ebpf = ebpfQ.data;

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="topbar">
        <h1 className="page-title">Support</h1>
      </div>

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">System</span>
          {data?.status === "ok" ? (
            <span className="status-badge ok">
              <span className="dot" />
              HEALTHY
            </span>
          ) : (
            <span className="status-badge muted">
              <span className="dot" />
              UNKNOWN
            </span>
          )}
        </div>
        <dl className="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
          <dt className="text-muted">Version</dt>
          <dd className="font-mono">{data?.version ?? "—"}</dd>
          <dt className="text-muted">Build</dt>
          <dd className="font-mono text-faint">{data?.commit ?? "—"}</dd>
        </dl>
      </section>

      {ebpf?.loader && (
        <section className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-title">Enforcement status</span>
              <p className="text-faint text-xs mt-1">
                Whether the eBPF rule engine actually loaded at API startup.
                When this reads "OFF", no rule enforces — regardless of how it's
                labelled on the Rules page.
              </p>
            </div>
            {ebpf.loader.loaded ? (
              <span className="status-badge ok">
                <span className="dot" />
                ENFORCING
              </span>
            ) : (
              <span className="status-badge critical">
                <span className="dot" />
                OFF
              </span>
            )}
          </div>
          {!ebpf.loader.loaded && (
            <div className="space-y-3 text-sm">
              <div className="text-danger">
                eBPF rule engine could not load. No rule on the Rules page is
                enforcing traffic, even those marked
                <code className="font-mono"> ACTIVE</code>.
              </div>
              {ebpf.loader.permission_denied && (
                <div className="text-muted">
                  <strong>Permission denied</strong> by capability / seccomp.
                  The API process needs{" "}
                  <code className="font-mono">CAP_BPF</code> +{" "}
                  <code className="font-mono">CAP_NET_ADMIN</code>. Bare-metal:
                  the systemd unit already grants these; re-run{" "}
                  <code className="font-mono">scripts/install.sh</code>
                  on a stale unit. Docker:{" "}
                  <code className="font-mono">cap_add: [BPF, NET_ADMIN]</code>.
                </div>
              )}
              {(ebpf.loader.missing_features ?? []).length > 0 && (
                <div className="text-muted">
                  <strong>Kernel features missing:</strong>{" "}
                  {(ebpf.loader.missing_features ?? []).join(", ")}. The loader
                  requires Linux ≥ 5.17 for{" "}
                  <code className="font-mono">bpf_loop</code>.
                </div>
              )}
              {ebpf.loader.error && (
                <details>
                  <summary className="text-faint cursor-pointer">
                    Loader error (raw)
                  </summary>
                  <pre className="mt-2 text-xs text-muted font-mono whitespace-pre-wrap">
                    {ebpf.loader.error}
                  </pre>
                </details>
              )}
              <div className="text-faint text-xs">
                Last load attempt:{" "}
                {new Date(ebpf.loader.last_attempt_at).toLocaleString()}
              </div>
            </div>
          )}
        </section>
      )}

      {ebpf &&
        (() => {
          const programs = ebpf.programs ?? [];
          return (
            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="panel-title">eBPF data plane</span>
                  <p className="text-faint text-xs mt-1">
                    Programs the API has attached. Cross-check with
                    <code className="font-mono"> bpftool prog show</code> on the
                    host.
                  </p>
                </div>
                <span className="text-faint text-xs">
                  {programs.length} attached
                </span>
              </div>
              {programs.length === 0 ? (
                <p className="text-muted text-sm">
                  No eBPF programs attached. Locations created at runtime should
                  auto-attach; if you see this with active rules, the kernel
                  side is silent and rules can't enforce.
                </p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-muted text-left">
                      <th className="py-2 font-medium">Interface</th>
                      <th className="py-2 font-medium">Hook</th>
                      <th className="py-2 font-medium">Program</th>
                      <th className="py-2 font-medium text-right">Prog ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {programs.map((p, i) => (
                      <tr
                        key={`${p.iface}-${p.hook}-${i}`}
                        className="border-t border-[var(--color-line)]"
                      >
                        <td className="py-2 font-mono">{p.iface}</td>
                        <td className="py-2 text-muted">{p.hook}</td>
                        <td className="py-2 text-muted">{p.program}</td>
                        <td className="py-2 text-right font-mono">
                          {p.prog_id || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {ebpf.pin_path && (
                <p className="text-faint text-xs mt-3">
                  Maps pinned at{" "}
                  <code className="font-mono">{ebpf.pin_path}</code>
                </p>
              )}
            </section>
          );
        })()}

      {warnings.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <span className="panel-title">Recent kernel warnings</span>
            <span className="text-faint text-xs">
              last {warnings.length}, auto-clears after 15 min
            </span>
          </div>
          <ul className="space-y-2 text-sm">
            {warnings.map((w, i) => (
              <li
                key={i}
                className="flex items-start gap-3 border-t border-[var(--color-line)] pt-2 first:border-t-0 first:pt-0"
              >
                <span className="status-badge warning shrink-0">
                  <span className="dot" />
                  {w.origin}
                </span>
                <div className="min-w-0">
                  <div className="text-muted">{w.message}</div>
                  <div className="text-faint text-xs mt-0.5">
                    {new Date(w.occurred_at).toLocaleString()}
                    {w.iface ? ` · ${w.iface}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="panel">
        <div className="panel-header">
          <span className="panel-title">Documentation</span>
        </div>
        <ul className="space-y-2 text-sm">
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub#readme"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Getting started
            </a>
          </li>
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub/blob/main/docs/user-guide/README.md"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Admin guide
            </a>
          </li>
          <li>
            <a
              href="/api/v1/openapi.yaml"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              API reference (OpenAPI)
            </a>
          </li>
          <li>
            <a
              href="https://github.com/tomeksdev/NexusHub/issues"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Report a bug
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
