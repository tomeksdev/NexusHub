-- 007_interface_address_inet.down.sql
-- Reverts 007 by casting INET back to CIDR. This will FAIL if any row
-- currently holds an address with host bits set — that's intentional: such
-- a row cannot be expressed as CIDR, and silently dropping the host bits
-- would rename someone's peer from 10.8.0.1/24 to 10.8.0.0/24.
--
-- To roll back safely, first re-point any affected rows at their network
-- address and rebuild the host-IP accounting by hand.

BEGIN;

ALTER TABLE wg_interfaces
    ALTER COLUMN address TYPE CIDR USING address::cidr;

COMMIT;
