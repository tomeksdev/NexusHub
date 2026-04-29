-- 001_users_auth.down.sql

BEGIN;

DROP TRIGGER IF EXISTS users_set_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS user_role;

COMMIT;
