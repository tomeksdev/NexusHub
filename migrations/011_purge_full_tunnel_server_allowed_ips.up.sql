-- 011_purge_full_tunnel_server_allowed_ips.up.sql
-- Strip 0.0.0.0/0 and ::/0 from wg_peers.allowed_ips (server-side only).
--
-- Round 13 added a backend validation that rejects these CIDRs on new
-- writes to the server-side allowed_ips column, but pre-existing rows
-- were grandfathered. On startup the wg reconciler pushes the DB state
-- to the kernel verbatim, so a peer with 0.0.0.0/0 stored from before
-- the validation landed kept appearing in `wg show` — defeating the
-- whole point of per-peer source validation.
--
-- This migration removes those entries from every row. If a row's
-- allowed_ips would end up empty after the purge, leave a single
-- /32 (or /128) of the peer's assigned_ip — that's the minimal viable
-- value the WG kernel module needs to accept the peer's own packets.
-- The handlers' Create + Update paths already enforce this invariant
-- for new writes; this migration brings legacy data in line.
--
-- The client_allowed_ips column is intentionally NOT touched —
-- full-tunnel routing on the client side (0.0.0.0/0 in the peer's
-- exported .conf) is a legitimate operator choice.

BEGIN;

UPDATE wg_peers
SET allowed_ips = (
    SELECT COALESCE(
        array_agg(p) FILTER (WHERE p <> '0.0.0.0/0'::cidr AND p <> '::/0'::cidr),
        ARRAY[]::cidr[]
    )
    FROM unnest(allowed_ips) AS p
)
WHERE allowed_ips && ARRAY['0.0.0.0/0'::cidr, '::/0'::cidr];

-- If the purge emptied a row's allowed_ips, seed it with the peer's
-- assigned_ip as a single host prefix so the kernel still accepts the
-- peer at all. Cast assigned_ip (INET) → text → cidr to attach a host
-- mask (/32 or /128) — the INET form may carry an arbitrary prefixlen
-- and we want exactly the host route here.
UPDATE wg_peers
SET allowed_ips = ARRAY[
    (host(assigned_ip) || CASE WHEN family(assigned_ip) = 4 THEN '/32' ELSE '/128' END)::cidr
]
WHERE cardinality(allowed_ips) = 0;

COMMIT;
