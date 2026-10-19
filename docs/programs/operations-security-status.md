# Operations/security implementation status and agent handoff

Updated: 19 October 2026.

## Current state

OPS-001's design contract is finalized. OPS-002 now implements application/environment/component
inventory behind `OPERATIONS_INVENTORY_ENABLED` (default false). No integration credential,
event collector, probe, incident engine or live Rokela PDF connection is implemented.
Source baseline reconciled against `b7c0c79`, including OPS-001 and the compatible ESLint toolchain.

| Task    | State                                 | Verification/evidence                                                                                                                        |
| ------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below. |
| OPS-002 | Implemented; local validation         | Inventory API, store contracts, PostgreSQL migration/grants, safe errors, atomic audit and opt-in rollout.                                   |
| OPS-003 | Ready; not implemented                | Scoped credential protocol specified; no credential runtime exists.                                                                          |
| OPS-004 | Not started; depends on OPS-003       | Nine strict backend event types specified; no durable ingestion runtime exists.                                                              |
| OPS-005 | Not started; depends on OPS-002/004   | Health semantics specified; network probes remain disabled.                                                                                  |
| OPS-006 | Not started; depends on OPS-004/005   | Incident/notification design only.                                                                                                           |
| OPS-007 | Not started; depends on OPS-004/006   | Rokela PDF brief aligned with accepted event contract; no live connection.                                                                   |
| OPS-008 | Not started; depends on OPS-006       | Existing recovery runbook is not restore evidence.                                                                                           |

## Next action: OPS-003

Reconcile the credential contract against current inventory code and any preserved local work
before implementation. Add per-environment, purpose-bound integration credentials with one-time
secret responses, digest-only persistence, fresh MFA, rotation overlap, revocation and strict
metadata-only reads. Keep integration authority separate from sessions and license keys. Acquire
`operations_accounts` before descendant locks and bind in-transaction checks to the same connection;
never acquire an outer-pool connection while holding an inventory lock. Add negative, mutation,
PostgreSQL/app-role and contention evidence. Keep event ingestion planned until OPS-004.

No production credentials are needed for local acceptance. Production enablement, real recipients,
independent monitoring and recovery drills remain later gates.

## OPS-002 implementation entry

- **Task/state:** inventory implemented and locally verified; no production enablement.
- **Commit/PR:** [PR #23](https://github.com/baimasonga/security-system/pull/23), initial implementation
  commit `beaec96`; GitHub checks are started by this PR and remain separate from local evidence.
- **Behavior:** 15 session-authenticated inventory operations; admin/owner-only distinct permissions,
  active member ownership and optional active Product linkage, strict safe slugs/reason codes,
  immutable ancestry/codes, optimistic versions, terminal tombstones, parent lifecycle checks,
  scoped cursors, same-org acyclic component dependencies and ancestor-consistent FK constraints.
  All successful mutations append atomic audit; freeze preserves reads but refuses writes.
- **Persistence:** `packages/operations`, isolated memory snapshots, PostgreSQL adapter and migration
  `0017_operations_inventory`; four tables with SELECT/INSERT/UPDATE grants, no delete/truncate.
  A per-organization lock anchor serializes descendant mutations/graphs/caps. Transaction-bound
  authority checks prevent pool starvation with contending requests. The initial load experiment
  reproduced outer-pool exhaustion; the fix and a beyond-pool-capacity regression are included.
- **Verification:** Node 24.19.0, npm 11.9.0, PostgreSQL 17 on a managed Linux workspace. Full
  `npm run check` passed (784 passed, 3 skipped); 32 targeted PG/app-role checks passed. Seven deliberate mutations were caught
  (authorization, freeze, owner, parent lifecycle, cycle, audit, cap). Final `npm run test:db` passed: 626 tests across
  55 files, covering PostgreSQL and the least-privilege app role (347.35 seconds). Schema checks remain
  design-only for credentials/events; live OpenAPI drift covers implemented inventory.
- **Initial DB run:** all 622 tests passed, but legacy-upgrade teardown exceeded its old 10-second
  hook limit. Its database-drop cleanup now uses the same 60-second allowance as the shared
  schema harness. The final suite uses the throwaway runner default (fsync off); the independent
  contention run below used fsync on. Application assertions and production settings are unchanged.
- **Load:** `DATABASE_URL=<disposable local database> node tools/loadtest/operations.ts` with fsync
  on: 264 real HTTP requests, exactly 220 creates + 1 update + 43 conflicts; persisted 100 apps,
  20 environments, 100 components and exactly 221 operations audit records; audit verified; 1975 ms.
  This checks integrity under contention, not sustained production capacity. The historical V1
  licensing/refresh throughput baseline is not directly comparable to a new inventory workload.
- **Configuration applied:** local test pools and `OPERATIONS_INVENTORY_ENABLED` in fixtures only.
  No production migrations, credentials, alerts or application integration were configured.
- **Known limits:** inventory has an API, not a fleet UI. Credential/event/health/incident runtime
  work remains pending. Owner membership removal is not implemented; its FK prevents removal
  without transfer. Freeze/authorization checks are transaction-bound; a freeze is not cancellation
  of a write already authorized/in flight. No successful restore or live connection is implied.
- **Rollback:** disable the flag / revert app release; retain inventory and audit evidence. See
  [rollout/rollback guide](../deploy/operations-inventory.md). Do not undo customer licensing state.
- **Next:** OPS-003 as above; preserve Business Admin and Rokela PDF commercial/auth boundaries.

## OPS-001 implementation entry

- **Task/state:** OPS-001 complete as design/schema work; runtime monitoring remains pending.
- **Commit/PR:** [PR #16](https://github.com/baimasonga/security-system/pull/16), initial implementation commit `d806be9`; this PR also records the final publication evidence.
- **Behavior/contracts:** reconciled current source, accepted ADR-029 and threat model; specified separate RBAC,
  immutable inventory/ownership, one-time 256-bit scoped bearer secrets, fresh-code credential management,
  bounded rotation/revoke races, strict versioned events, committed atomic acknowledgements, scoped canonical
  deduplication, privacy rules, quotas/retention/backpressure, unknown/stale health, no initial probes, and
  incident/outbox/freeze boundaries. No changes to production routes, auth grants, migrations or licensing.
- **Tests:** `npx vitest run --project unit tests/operations-planned-contract.test.ts` (25 schema checks);
  deliberate schema mutations cover event scope fields, attribute allow-list, enum privacy, batch cap, numeric
  bounds, metadata secret separation, rotation overlap and required management inputs. These checks validate
  the planned schemas only; they do not establish runtime authentication/atomicity/PII logging behavior.
- **Verification:** managed Linux workspace, Node 24.19.0 and npm 11.9.0. Full `npm run check` passed (770 tests passed, 3 skipped); `npm audit --audit-level=high` reported zero vulnerabilities. Eight deliberate schema mutations were caught. GitHub CI results are linked from the PR. PG/load checks are not applicable to this design-only
  task: no store, transaction or retention implementation changed. The existing live OpenAPI drift test remains active.
- **Configuration applied:** none; no production credentials or real alert destinations used.
- **Known gaps:** all OPS-002–008 runtime controls, source outbox, health history, incident delivery and live
  integrations remain unimplemented. Schemas cannot prove membership, ancestor relationships, clock windows,
  byte budgets, committed ACKs, deduplication or deletion; each requires later runtime tests.
- **Rollback:** revert these design/schema artifacts and dev-only validation dependencies; no data migration or
  commercial-state rollback is needed.
- **Next ready task:** OPS-002, inventory vertical slice as listed above.

## Evidence rules

- The owner reports Business Admin was tried first; source contains provisioning and development acceptance
  support. This handoff does not independently verify its live deployment.
- A feature is implemented only when code and tests exist. Fixtures are not production credentials; screenshots
  are not access-control tests; documentation is not evidence that a provider, backup, external anchor or alert
  channel is configured. Schema acceptance tests are not runtime authorization/persistence tests.
- Record commit/PR, tests/failures, configuration names, verification environment and remaining limits for each
  task. Never include credentials, private links, file contents or production exports.

### ESLint dependency integration — 2026-10-19

Merged the Dependabot ESLint 10.12.0 and `@eslint/js` 10.0.1 branches together
with `eslint-plugin-security` 4.2.0. The latter replaces the removed ESLint
context API that caused the lint crash. Resolved the package/lockfile conflicts
by retaining both ESLint 10 declarations and regenerating the lockfile with the
security plugin upgrade; frozen installation succeeds.

Preserved the ESLint 9 rule baseline by explicitly deferring the two newly
recommended rules, `preserve-caught-error` and `no-useless-assignment`. Existing
security rules remain enabled. Grouped the ESLint dependencies in Dependabot to
prevent future incompatible individual updates.

Verification: `npm ci`, `npm run check` (770 passed, 3 skipped), and
`npm audit --audit-level=high` (0 vulnerabilities) passed. An stdin unsafe-regex
probe in the platform source scope produced the expected security-rule warning,
confirming that the upgraded plugin executes. Evidence is in
`/tmp/eslint-integration-check.log`. These are local checks; remote CI and native
Windows execution have not been observed. This integration changes development
tooling only; no application/database security boundaries were changed.

The unrelated local OPS-003 implementation remains preserved in the original
workspace and is not included in this dependency integration. Next: observe the
new CI run, then reconcile the local OPS implementation with the accepted
upstream contracts before continuing feature work.
