-- 008_peer_client_allowed_ips.up.sql
-- Add client_allowed_ips to wg_peers.
--
-- WireGuard's `AllowedIPs` field is asymmetric: on the SERVER side it
-- means "source IPs accepted from this peer / destinations routed to
-- this peer", which is what we already store as `allowed_ips`. On the
-- CLIENT side (the peer's own .conf) it means "destinations to route
-- through the tunnel" — typically the server's interface CIDR for
-- split-tunnel or 0.0.0.0/0,::/0 for full-tunnel.
--
-- These are different values. Before this migration the exported .conf
-- copied the server-side allowed_ips into the client's [Peer] block,
-- which produced a peer that routed only its own /32 through the
-- tunnel. Adding a dedicated column lets operators control the client
-- view per peer; renderWgQuickConfig falls back to the interface's CIDR
-- when this is empty so the default at least reaches the server.

BEGIN;

ALTER TABLE wg_peers
    ADD COLUMN client_allowed_ips CIDR[] NOT NULL DEFAULT '{}';

COMMIT;
