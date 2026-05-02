-- 009_interface_listen_port_unique.up.sql
-- Reject duplicate listen_port values across wg_interfaces.
--
-- A WireGuard kernel device cannot share a UDP port with another wg
-- interface — the second one fails to bind silently and packets get
-- routed to whichever device claimed the port first. Surfacing the
-- conflict at insert time lets the API return a clean 409 instead of
-- letting the operator discover the breakage post-deploy.
--
-- Operators running multiple unrelated NexusHub instances on one host
-- need their own host port-spaces; that scenario is out of scope.

BEGIN;

ALTER TABLE wg_interfaces
    ADD CONSTRAINT wg_interfaces_listen_port_unique UNIQUE (listen_port);

COMMIT;
