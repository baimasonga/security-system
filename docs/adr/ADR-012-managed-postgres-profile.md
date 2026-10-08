# ADR-012 — Managed PostgreSQL profile (Supabase): private schema, least-privilege role, TLS

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (database credentials and privileges, new deployment surface)
- Strengthens **R-13** (database-level tampering) and adds **R-17** (managed-platform exposure). Deployment guide: [docs/deploy/supabase.md](../deploy/supabase.md).

## Context

The platform only needs PostgreSQL, so a managed provider such as Supabase is a legitimate home for it. Managed platforms add
three things the local setup never had to consider: (1) tables in `public` can be reachable through the provider's generated
HTTP API under well-known roles (`anon`, `authenticated`, `service_role`); (2) the default account is the owner of everything,
so a compromised application could disable the audit triggers or truncate evidence; (3) the database is reached across a
network, through poolers that restrict session state, so TLS and startup parameters matter.

## Decision

1. **Private schema.** `DB_SCHEMA` (default unset = the role's default schema). `npm run migrate` creates the schema and
   migrates inside it, including the migration ledger. The API refuses to start when its connection does not land in `DB_SCHEMA`.
   The schema is selected by `ALTER ROLE … SET search_path`, not by connection options: poolers reject startup parameters.
2. **Two roles.** The _owner_ migrates (`DATABASE_MIGRATE_URL`, direct connection); the _application role_ (`DATABASE_URL`) owns
   nothing. `npm run db:grants` (`db/grants.ts`) gives it only what the code needs: DML per table from an explicit policy
   (`TABLE_PRIVILEGES`), `USAGE` on the schema (no `CREATE`), and no `UPDATE`/`DELETE`/`TRUNCATE`/`TRIGGER` on `audit_events`
   or `audit_anchors`, no `DELETE` on `audit_chains`, no `TRUNCATE`/`TRIGGER`/`REFERENCES` anywhere. A table missing from the
   policy makes the tool fail, and a test asserts the policy and the migrated schema match: a new table forces a decision.
   The grant step revokes before it grants and is idempotent; it also removes any access the API roles have to the schema.
3. **Behavioural proof.** A second PostgreSQL test project (`db-approle`) re-runs the licensing, API, security and end-to-end
   suites with the application connected as that role. If any code path needs a privilege the profile withholds, it fails.
4. **TLS fails closed.** Production rejects a remote `DATABASE_URL` without `sslmode=require|verify-ca|verify-full`, unless
   `DATABASE_CA_FILE` provides a CA (then the certificate is verified and the URL's `sslmode` is overridden) or
   `DATABASE_INSECURE_TRANSPORT=true` accepts the risk explicitly.
5. **Role judgement at startup.** A superuser connection is refused in production (`DB_ALLOW_SUPERUSER=true` to accept);
   owning tables or bypassing row-level security is logged as a warning.
6. **`npm run db:check`** verifies a live connection against the profile (encrypted, private schema, migrations current, not
   superuser/owner, no DDL, audit tables append-only, nothing missing, API roles locked out, schema not listed in the API
   gateway's `pgrst.db_schemas`) with a pure, exhaustively tested judgement function. Exit status is suitable for CI/deploy gates.
7. **Not adopted:** Supabase Auth (the server remains the only authority; identity stays in `@trust/auth`), the Data API,
   Realtime, Storage (including as the audit witness — same trust domain as the database).

## Alternatives considered

| Option                                                   | Why not                                                                                                                                                                                                                       |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keep tables in `public`, rely on RLS                     | RLS with no policy is deny-by-default for API roles but a single mistaken policy or later `GRANT` exposes everything; and an owner-level application bypasses RLS anyway. A private schema plus no grants is simpler to audit |
| Application connects as `postgres`                       | One SQL injection or stolen credential could drop triggers and rewrite or truncate the audit log undetected until the next witness check                                                                                      |
| `options=-c search_path=…` on the pool                   | Rejected by transaction-mode poolers; role-level settings work everywhere                                                                                                                                                     |
| Enable RLS on every table with a policy for the app role | Extra moving parts with no additional protection over grants, given the app role never shares a schema with API roles                                                                                                         |

## Consequences

- A compromised application can no longer disable the audit triggers or rewrite/truncate evidence at the database level;
  the external witness (ADR-010) then only has to cover a compromised _owner_.
- Misconfiguration (wrong schema, public schema, API roles with access, no TLS, superuser) is caught at startup or by `db:check`.
  − Operators run one extra command (`db:grants`) after each migration, and keep two credentials.
  − The provider's dashboard users and anyone with the owner role remain inside the trust boundary (R-13 residual → witness).
  − Not verified against a live Supabase project; connection-mode details are from documentation and must be confirmed. Throughput
  on managed compute and across the provider's pooler is unmeasured.
