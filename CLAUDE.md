# Working agreements for this repository

This is a security-critical trust platform. Prefer boring, auditable code. Correctness first.

## Commands

- `npm run check` — format check, lint + architecture boundaries, typecheck, unit/integration/security tests (must pass before any push)
- `npm run test:db` — PostgreSQL tests against a throwaway cluster (or `DATABASE_URL`); also re-runs the behavioural suites on PG
- `npm run migrate` — apply SQL migrations (`DATABASE_URL` required)
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
