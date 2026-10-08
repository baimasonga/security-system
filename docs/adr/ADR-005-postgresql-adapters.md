# ADR-005 — PostgreSQL adapters: contract-tested, lock-based, schema-guarded

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (tenant isolation, audit integrity, key custody metadata)

## Context

ADR-001 made PostgreSQL the system of record behind ports, with in-memory
adapters for tests. Persistence is where several security properties become
real: tenant isolation, single-use challenges, the device limit, the audit chain.

## Decision

1. **Adapters live in `services/platform-api/src/db/`**, not in the domain packages, so domain code never imports `pg` (enforced by the boundary checker). One adapter per port: `PgAuthStore`, `PgLicensingStore`, `PgAuditLog`, `PgTelemetrySink`, `PgKeyStore`.
2. **One definition of correct behaviour per port**: contract suites (`packages/*/test/*contract.ts`) run unchanged against the in-memory _and_ PostgreSQL adapters. A behavioural difference is a bug in one of them (the first run found one: the in-memory store accepted a cross-tenant lease). Beyond contracts, the full licensing, API, security and end-to-end suites also run against PostgreSQL, each test in its own freshly migrated schema.
3. **Concurrency by explicit row locks, READ COMMITTED.** Anything that counts or changes a license's activations first calls `findLicenseForUpdate` (`SELECT … FOR UPDATE`); device-auth reads inside a transaction lock the activation row. Lock order is always license → activation. Challenge consumption is one atomic `UPDATE … WHERE consumed_at IS NULL`. Device registration is `INSERT … ON CONFLICT (thumbprint) DO NOTHING` and returns the surviving row, so a racing duplicate converges instead of failing.
4. **Audit appends are serialized** with a transaction-scoped advisory lock and chained inside the transaction (`prev_hash` = last row's hash). Verification streams the table in pages through the same `ChainVerifier` the in-memory log uses. Database triggers additionally reject UPDATE/DELETE/TRUNCATE.
5. **Constraint violations are translated** to the exact errors the in-memory adapters throw (`duplicate_key`, `cross_tenant_reference`, `trial_exists`, …); the service layer never sees SQLSTATE codes.
6. **Schema is a deployment precondition, not a side effect of start-up.** Migrations are applied by `npm run migrate` (checksummed, advisory-locked, immutable history). The server **refuses to start** if the database lacks a known migration or has one it does not know (`assertSchemaCurrent`).
7. **Signing keys:** only public metadata and lifecycle state are stored (`signing_keys`); private material comes from the secret store/KMS. `kid` is derived from the public key, so restarts are stable. Key rotation = configure the new key and restart: the old key is persisted as `deprecated` (verify-only) and a restart with a rotated-out or revoked key is refused. Every transition is persisted and audited.
8. **Production requires `PERSISTENCE=postgres`**; in-memory storage in production is refused at start-up.

## Consequences

- The same tests prove the same behaviour on both stores; mutation checks show the contract/concurrency tests fail if a lock, atomic guard, rollback or tenant scope is removed.
- Restarts no longer lose accounts, licenses, activations, the audit chain, or key state.
  − No load testing yet. Audit atomicity and deadlock retry were added in [ADR-006](ADR-006-atomic-audit-and-transaction-retry.md).
  − The in-memory adapters must be kept in step with PostgreSQL semantics by the contract suites; adding a port method requires adding it to the contract first.
