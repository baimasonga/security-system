# Deploying on Supabase (managed PostgreSQL)

Decision record: [ADR-012](../adr/ADR-012-managed-postgres-profile.md). The platform needs only PostgreSQL 15+ and a
connection string; it does **not** use Supabase Auth, the Data API, Realtime, Storage or Edge Functions. Everything below
exists to use Supabase's database _safely_, and the same steps apply to any managed PostgreSQL.

> The Supabase-specific details here (connection hosts and ports, pooler user format, dashboard settings) were written
> from documentation knowledge and have **not** been exercised against a live project. Verify each against the current
> Supabase documentation, then run `npm run db:check` — it checks the result, not the instructions.

## What you end up with

| Role                                    | Used by                                                                          | Can                                                                                                          | Cannot                                                                                  |
| --------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| `postgres` (owner)                      | migrations and `db:grants`, from an operator's machine or CI — **never the API** | everything                                                                                                   | —                                                                                       |
| `trust_app`                             | the API (`DATABASE_URL`)                                                         | read/write the platform's tables as listed in `db/grants.ts`; **append** to `audit_events` / `audit_anchors` | UPDATE/DELETE/TRUNCATE evidence, create or drop objects, disable triggers, own anything |
| `anon`, `authenticated`, `service_role` | Supabase's Data API                                                              | nothing in the `trust` schema                                                                                | —                                                                                       |

The tables live in a private schema (`trust`), not `public`, so the auto-generated API has nothing to expose even if
someone later enables it.

## Steps

1. **Create the project** in the region closest to where the API runs. The platform makes ~10–12 sequential statements
   per device call, so the round trip to the database sets your throughput (≈ 200 flows/s per instance at 2 ms).
2. **Data API:** leave `trust` out of "Exposed schemas" (or disable the Data API for this project). Do not use the
   project's `anon`/`service_role` keys anywhere in this system.
3. **Create the schema and role:** run [`supabase-setup.sql`](supabase-setup.sql) in the SQL editor, after replacing the password.
4. **Migrate** with the owner's _direct_ connection (migrations use session state and an advisory lock):
   ```sh
   DATABASE_MIGRATE_URL='postgresql://postgres:<owner-password>@db.<ref>.supabase.co:5432/postgres?sslmode=require' \
   DB_SCHEMA=trust npm run migrate
   ```
5. **Grant:** run after **every** migration (it fails on a table without a policy, by design):
   ```sh
   DATABASE_MIGRATE_URL='…same…' DB_SCHEMA=trust APP_DB_ROLE=trust_app npm run db:grants
   ```
6. **Point the API at the app role.** Use the _session-mode_ pooler or the direct connection (see below):
   ```sh
   DATABASE_URL='postgresql://trust_app.<ref>:<app-password>@<pooler-host>:5432/postgres?sslmode=require'
   DB_SCHEMA=trust            # the API refuses to start if the role does not land in this schema
   DATABASE_CA_PEM='-----BEGIN CERTIFICATE-----…'   # the CA from the dashboard (SSL configuration), or DATABASE_CA_FILE=/path/ca.pem.
   # The driver treats sslmode=require as full verification and Supabase's CA is not publicly trusted, so without a CA you get
   # "self-signed certificate in certificate chain".
   PERSISTENCE=postgres  NODE_ENV=production   # plus the usual secrets, signing key and AUDIT_ANCHOR_URL
   ```
7. **Verify:** `DATABASE_URL=… DB_SCHEMA=trust npm run db:check` must print `OK` (warnings allowed, failures not).

## Connection modes

- **Direct connection** — simplest and fastest. May be IPv6-only depending on plan; check your runtime's networking.
- **Session-mode pooler (port 5432 on the pooler host)** — works with everything the platform does; user is `trust_app.<project-ref>`.
- **Transaction-mode pooler (port 6543)** — each of our transactions stays on one connection, so it should work, but it adds a
  hop on every statement and has not been tested. The platform sends **no startup parameters** (no `options=-c …`), which
  transaction poolers reject; schema and timeouts come from the role (`ALTER ROLE … SET`), step 3.
- Keep `DB_POOL_MAX` at 5–10 per instance, and `instances × DB_POOL_MAX` below the plan's connection limit (and the role's `CONNECTION LIMIT 40`).

## What the guards enforce

- Production refuses a remote `DATABASE_URL` without TLS (`sslmode=require|verify-ca|verify-full`), unless `DATABASE_CA_FILE`
  is set (then the server certificate is verified) or `DATABASE_INSECURE_TRANSPORT=true` accepts the risk.
- Production refuses to run as a database superuser unless `DB_ALLOW_SUPERUSER=true`. Startup always refuses when the
  connection does not land in `DB_SCHEMA`, and logs a warning if the role owns tables or bypasses row-level security.
- Rotating the app password: `ALTER ROLE trust_app PASSWORD '…'`, then roll the API. Migrating never needs the app role.

## Limits you should know about

- Anyone with the project owner role or dashboard access can still disable triggers and rewrite history. The least-privilege
  role protects against a compromised _application_; the external audit witness ([ADR-010](../adr/ADR-010-external-audit-anchor.md))
  protects against a compromised _database owner_. Do **not** use Supabase Storage as that witness — same trust domain.
- Backups and point-in-time recovery depend on the plan; run the restore drill, then `tools/verify-anchor.ts` on the restored copy.
- Capacity figures in the load-test report were measured on a local database. Re-run `npm run loadtest` against the real
  project (from a machine in the same region) before sizing.
