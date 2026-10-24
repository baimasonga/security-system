# Working agreements for this repository

This is a security-critical trust platform. Prefer boring, auditable code. Correctness first.

Cross-application monitoring work starts at [AGENTS.md](AGENTS.md), then the
[operations/security program](docs/programs/operations-security.md) and its
[current handoff](docs/programs/operations-security-status.md). Inventory, credential management, durable ingestion and health/history reads are implemented
behind separate source flags; manual incident triage has a separate flag. Automatic rules and the portal notification outbox have a separate opt-in flag; incident email to the verified rule creator has its own opt-in flag; operator-configured Warrior HTTPS probes have their own opt-in flag; webhooks and other providers remain unconfigured. Security findings and recovery reports have a separate opt-in flag and remain explicitly unverified administrator evidence. Keep evidence/status current.

## Commands

- `npm run check` — format check, lint + architecture boundaries, typecheck, unit/integration/security tests (must pass before any push)
- `npm run test:db` — PostgreSQL tests against a throwaway cluster (or `DATABASE_URL`); also re-runs the behavioural suites on PG, once as superuser (`db`) and once as the least-privilege app role (`db-approle`)
- `npm run loadtest -- --scenario <name> …` — open-loop load/soak tool against a real server + PostgreSQL (`--assert-clean` exits non-zero on any error)
- `DATABASE_URL=… node tools/verify-anchor.ts <manifest|witness.jsonl>` — check the live audit log against anchors held by the external witness (ADR-010)
- `npm run migrate` — apply SQL migrations (`DATABASE_MIGRATE_URL` or `DATABASE_URL`; `DB_SCHEMA` for a private schema)
- `npm run db:grants` / `npm run db:check` — least-privilege grants for the app role / verify a connection against the managed-database profile (ADR-012); run `db:grants` after every migration, and add every new table to `TABLE_PRIVILEGES` (`db/grants.ts`)
- `npm run bootstrap:operator -- --email … --reason …` — promote an existing user to platform operator (deployment tooling, audited; the only way to create the first operator)
- `npm run format` — Prettier write
- `node tools/gen-lease-vectors.ts > docs/api/lease-test-vectors.json` — only when the lease wire format changes (ADR required)

## Rules

- Specify before building: spec/ADR/threat-model updates accompany any trust-boundary change. Update `docs/` in the same change.
- TDD for security-sensitive code; every control needs a negative-path test. Mutation-check new security tests (break the control, watch the test fail).
- Erasable TypeScript only (no enums, parameter properties, namespaces); relative imports use `.ts` extensions.
- Respect package boundaries (`tools/check-boundaries.mjs`). `sdk-core` may import only `@trust/crypto/verify`.
- Never: log secrets/tokens/keys; put private keys in the repo or clients; trust client-provided plan state; authorize only in a frontend; treat a license key as authority; return different errors that reveal other tenants' objects (use 404).
- Every operator/admin mutation needs a mandatory `reason` and an audit event. Unknown request fields are rejected (strict zod).
- Licensing failures degrade to states; they must never delete or lock user documents.
- Keep `docs/api/openapi.yaml` in sync with routes (a drift test enforces it).
- Production requires `PERSISTENCE=postgres` and fails closed on weak/missing config (`config.ts`); do not weaken those guards.
- Adding a store-port method? Add it to the contract suite first (`packages/*/test/*contract.ts`) so every adapter must satisfy it. PostgreSQL work that counts/changes activations must lock the license row (`findLicenseForUpdate`).
- State changes that must be audited write their audit event through `tx.audit.append(...)` inside `store.transaction(...)` — never `audit.append` after the fact (ADR-006). Only refusals/denials (no state change) use the standalone `audit.append`.
- Store-transaction callbacks must be re-runnable (PostgreSQL retries them after deadlocks): derive state from reads inside the transaction, no irreversible side effects. Lock order is always license → activation.
- Changes to locking, transactions, the audit path, retention or schema: re-run the relevant load-test scenarios and compare with `docs/performance/load-test-v1.md`. Check every measured outcome against its _expected_ value — a result that "looks fine" can come from a setting that never applied.
- New operator config knobs need a test proving they change behaviour end to end (see `maintenance.test.ts`); patch/refactor scripts must assert that their edit anchors matched.
