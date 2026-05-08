// ConfigPreview renders the operator-relevant slice of the
// wg-quick config that the peer will receive, derived from the
// modal's current form state. It deliberately only shows the
// fields that change with operator input — keys, server pubkey,
// PSK are server-rendered and not interesting until export.
//
// Used in PeerCreateModal and PeerEditModal so the operator can
// see the effect of their changes before saving.

interface Props {
  // The /32 / /128 the peer tunnel address will become. Empty
  // string = blank input, which renders a placeholder.
  assignedIP?: string;
  // The location's CIDR (e.g. 10.8.0.0/24). Used as the default
  // for [Peer] AllowedIPs when the operator hasn't supplied
  // client_allowed_ips. Undefined means "no location selected".
  interfaceCIDR?: string;
  // Operator-supplied client_allowed_ips. Empty array = use
  // interfaceCIDR.
  clientAllowedIPs: string[];
  // Optional override at peer scope. Empty string falls through to
  // the location's endpoint.
  endpointOverride?: string;
  locationEndpoint?: string | null;
}

function maskedFromCIDR(cidr?: string): string {
  if (!cidr || !cidr.includes("/")) return cidr ?? "";
  // Render the network as-is — e.g. "10.8.0.0/24" stays
  // "10.8.0.0/24". This is the same shape the renderer outputs.
  return cidr;
}

function inferAddressBits(ip: string): string {
  // IPv6 if there are more than one colon; otherwise IPv4.
  return ip.includes(":") && (ip.match(/:/g) ?? []).length > 1
    ? "/128"
    : "/32";
}

export function ConfigPreview({
  assignedIP,
  interfaceCIDR,
  clientAllowedIPs,
  endpointOverride,
  locationEndpoint,
}: Props) {
  const addr = assignedIP?.trim() ?? "";
  const addressLine = addr
    ? `Address = ${addr}${inferAddressBits(addr)}`
    : "Address = …";

  const allowed =
    clientAllowedIPs.length > 0
      ? clientAllowedIPs.join(", ")
      : maskedFromCIDR(interfaceCIDR) || "…";

  const endpoint =
    endpointOverride?.trim() ||
    locationEndpoint ||
    "(inherits from location default)";

  return (
    <details className="border-t border-[var(--color-line)] pt-3">
      <summary className="text-sm text-muted cursor-pointer select-none">
        Config preview
      </summary>
      <pre
        className="rounded-md p-3 mt-2 text-xs font-mono overflow-auto whitespace-pre-wrap break-all"
        style={{
          background: "#111",
          border: "1px solid var(--color-line-strong)",
          color: "var(--color-text)",
        }}
      >
        {`[Interface]
${addressLine}

[Peer]
AllowedIPs = ${allowed}
Endpoint = ${endpoint}`}
      </pre>
      <span className="field-hint">
        Keys, server public key, and PSK are filled in when you download the
        .conf.
      </span>
    </details>
  );
}
