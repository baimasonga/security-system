# Operations/security implementation status and agent handoff

Updated: 19 October 2026.

## Current state

OPS-001's design contract is finalized with executable planned-schema checks. No operations-monitoring API,
integration credential, probe, incident engine or live Rokela PDF connection is implemented by this change.
Source baseline reconciled against `84a9862`, which includes the merged update-security work in
[PR #15](https://github.com/baimasonga/security-system/pull/15). Recheck current code before the next task.

| Task    | State                                 | Verification/evidence                                                                                                                        |
| ------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below. |
| OPS-002 | Ready; not implemented                | Inventory implementation is the next task; contract ready.                                                                                   |
| OPS-003 | Not started; depends on OPS-002       | Scoped credential protocol specified; no credential runtime exists.                                                                          |
| OPS-004 | Not started; depends on OPS-003       | Nine strict backend event types specified; no durable ingestion runtime exists.                                                              |
| OPS-005 | Not started; depends on OPS-002/004   | Health semantics specified; network probes remain disabled.                                                                                  |
| OPS-006 | Not started; depends on OPS-004/005   | Incident/notification design only.                                                                                                           |
| OPS-007 | Not started; depends on OPS-004/006   | Rokela PDF brief aligned with accepted event contract; no live connection.                                                                   |
| OPS-008 | Not started; depends on OPS-006       | Existing recovery runbook is not restore evidence.                                                                                           |

## Next action: OPS-002

Read AGENTS.md, CLAUDE.md, the program, ADR-029, threat model, and
[operations contract](../api/operations-contract.md). Implement only application/environment/component inventory:

1. Add `packages/operations` and its enforced dependency allow-list; introduce inventory entities/store port
   with injected organization authorization and optional active Product validation. Define store contracts first.
2. Add isolated memory and PostgreSQL adapters, next numbered migration, ancestor keys/immutable-code uniqueness,
   optimistic versions and parent locking. Add every table to `TABLE_PRIVILEGES`, with least-privilege app-role tests.
3. Introduce explicit `ops:read` and `ops:manage_inventory` permission grants for admin/owner only, safe labels,
   required reason codes and atomic audit, owner membership checks and freeze handling. Preserve existing licenses
   and ordinary customer access. Implement tombstones, disabled/archived parent semantics and same-org acyclic dependencies.
4. Move only implemented inventory operations from the planned OpenAPI into the live contract. Keep credentials,
   events, incidents and probe routes planned. Add the real HTTP tenant/role/refusal/audit rollback tests and relevant
   PG/concurrency/load evidence. Update this handoff with exact results and next action.

No live credentials are needed for inventory implementation. Production endpoint/credential setup, controlled
alert destinations, independent monitoring and restore exercises remain later rollout prerequisites.

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
