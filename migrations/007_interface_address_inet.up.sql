-- 007_interface_address_inet.up.sql
-- Switch wg_interfaces.address from CIDR to INET.
--
-- The semantic value of this column is "the interface's host IP within the
-- subnet" (e.g. 10.8.0.1/24 — `.1` on a /24). That's the wg-quick convention
-- and the value the kernel expects. PostgreSQL's CIDR type rejects any
-- address with host bits set (it only accepts network addresses like
-- 10.8.0.0/24), which forces callers to strip the host portion before
-- insert and reconstruct it afterwards — exactly the information we need
-- to keep. INET has no such restriction and round-trips faithfully.
--
-- Existing rows: any production row stored here was necessarily a network
-- address (the CIDR check left no alternative), so the ALTER is safe — it
-- widens the domain, never narrows it.

BEGIN;

ALTER TABLE wg_interfaces
    ALTER COLUMN address TYPE INET USING address::inet;

COMMIT;
