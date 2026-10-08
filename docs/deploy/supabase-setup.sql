-- Run ONCE as the project owner (the `postgres` role in the Supabase SQL editor). See docs/deploy/supabase.md.
-- (Written for Supabase, where the roles anon, authenticated and service_role exist; on other platforms drop section 4.)
-- Replace the password; generate it with a password manager (>= 24 random characters). Do not commit the result.

-- 1. A private schema. NEVER add it to the Data API's "Exposed schemas".
CREATE SCHEMA IF NOT EXISTS trust;

-- 2. The application's role. It owns nothing; `npm run db:grants` gives it exactly the privileges it needs.
CREATE ROLE trust_app LOGIN PASSWORD 'CHANGE-ME-generate-a-long-random-password' CONNECTION LIMIT 40;

-- 3. Role-level settings travel through connection poolers (startup options do not).
ALTER ROLE trust_app SET search_path = trust;
ALTER ROLE trust_app SET statement_timeout = '30s';
ALTER ROLE trust_app SET idle_in_transaction_session_timeout = '30s';

-- 4. The API roles must never reach the platform's tables (db:grants re-asserts this after every migration).
REVOKE ALL ON SCHEMA trust FROM anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA trust REVOKE ALL ON TABLES FROM anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA trust REVOKE ALL ON SEQUENCES FROM anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA trust REVOKE ALL ON FUNCTIONS FROM anon, authenticated, service_role;
