# Operations/security implementation status and agent handoff

Updated: 19 October 2026.

## Current state

OPS-001 design, OPS-002 inventory and OPS-003 credential management are implemented.
Inventory and credentials have separate opt-in flags, both default false. Credential
verification supplies a guarded transaction primitive, not an event collector.
No events/health/incidents runtime or live Rokela PDF connection is implemented.
OPS-002 and OPS-003 were merged together in PR #24 (`919dff77`); PR #23 was
closed as superseded. Both operations flags are enabled on the existing Warrior
Railway production service. This enabled backend management APIs; dashboard wiring is now implemented on the
working branch described below. Application event ingestion remains unimplemented. See the production rollout evidence below.

| Task    | State                                 | Verification/evidence                                                                                                                        |
| ------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below. |
| OPS-002 | Implemented; local validation         | Inventory API, store contracts, PostgreSQL migration/grants, safe errors, atomic audit and opt-in rollout.                                   |
| OPS-003 | Implemented; local verification       | Scoped secrets, fresh MFA, rotation/revoke, guarded transaction verification and digest-only storage.                                        |
| OPS-004 | Ready; not implemented                | Nine strict backend event types specified; durable ingestion is next.                                                                        |
| OPS-005 | Not started; depends on OPS-002/004   | Health semantics specified; network probes remain disabled.                                                                                  |
| OPS-006 | Not started; depends on OPS-004/005   | Incident/notification design only.                                                                                                           |
| OPS-007 | Not started; depends on OPS-004/006   | Rokela PDF brief aligned with accepted event contract; no live connection.                                                                   |
| OPS-008 | Not started; depends on OPS-006       | Existing recovery runbook is not restore evidence.                                                                                           |

## Production enablement — 19 October 2026

- User explicitly authorized enabling implemented features. Combined PR #24's exact
  head `e2844f3` passed format/lint/types/unit, PostgreSQL owner/app-role plus load
  smoke, Windows SDK, dependency/secret scanning and CodeQL checks. The older PR
  #23 had a passkey asynchronous-signal assertion failure; the combined release's
  complete PostgreSQL suite passed. This is not evidence that the test race is fixed.
- Existing Railway project `victorious-commitment`, service `@trust/platform-api`,
  production environment; repository/default branch retained. No duplicate service
  was created and no Business Admin licensing or existing secret was replaced.
- Set `OPERATIONS_INVENTORY_ENABLED=true` and
  `OPERATIONS_CREDENTIALS_ENABLED=true`, reusing the existing MFA encryption key.
  Widened watch patterns from only `/services/platform-api/**` to `/**` so shared
  packages and migrations trigger deployment. Moved migrations/grants/profile
  checks into pre-deploy; the start command now only starts the API.
- Source merge `919dff77bf8fc67b73c166833b1f0a28e4a86a37` deployed successfully
  as `439ed945-7db6-4a33-972c-cccc9b8fb32b`. Logs confirm migrations 0017/0018
  applied and 90 application-role grant statements applied.
- Enabled-settings deployment `6d8966b9-d8c7-421a-999e-43622c351767` reached
  SUCCESS. Logs confirm schema through 0018, verified database TLS and application
  role startup; Railway's `/healthz` health check succeeded. Staged changes are clear.
- Verification limit: direct public HTTP checks from this managed session hit its
  outbound proxy's CONNECT 403, not an application response. No authenticated live
  inventory/credential flow was performed, and no production credential was issued.
  An organization admin/owner must enroll MFA and use the documented APIs; a fleet
  management UI remains unimplemented. Events, health, incidents and live Rokela PDF
  integration remain unimplemented. Existing external audit anchoring remains disabled.
- Rollback: disable credentials first, then inventory if required; keep migrations,
  stored digests and audit history. Do not replace the MFA key or licensing secrets.

## Dashboard wiring — implementation and continuation checkpoint

User requested usable dashboard controls for the implemented APIs, followed by the
remaining monitoring program, with a durable handoff for the next agent. Work branch: `feat/operations-dashboard`, based on
production merge `919dff77` plus the production evidence commit `8b44184` (PR #25).
Do not mistake this working branch for a production deployment.
Implementation commit `e522703`, published as [PR #28](https://github.com/baimasonga/security-system/pull/28).
CI/merge/rollout remain pending; the last confirmed live deployment is still the
backend-only `6d8966b9-d8c7-421a-999e-43622c351767`.
Default-branch compatibility update PR #26 (`5f89809`) was subsequently integrated
without conflicts (`7663423`). Its exact-source local replay passed `npm run check`
with 802 tests and 3 skips, plus all four browser workflows. CI/merge/rollout of
this combined head remain pending; the extra unit test comes from PR #26.

- Added `web/operations.mjs` and Applications navigation: applications, environments,
  components/dependencies, ownership/Product/criticality editing, versioned lifecycle
  changes, retained-record lookup and credential issue/rotate/revoke with fresh MFA.
- Scope is captured per visit. Navigation/workspace/session changes invalidate async
  results; credential factors are cleared before requests, secrets use one-time modal
  presentation and are cleared on close/navigation/pagehide. Backend authorization and
  APIs are unchanged. Disabled/archived parent credential revocation stays available.
- Added Playwright Core as a development dependency, a separate `portal` Vitest project,
  `npm run test:portal`, and a CI browser job. Local browser uses
  `CHROMIUM_PATH=/usr/bin/chromium npm run test:portal`; CI installs Chromium using
  `npx playwright-core install --with-deps chromium`. No provider credentials needed.
- Four real browser/API flows pass locally: inventory/dependencies, MFA credentials,
  disabled/archived emergency revoke, pagination/retained lookup, delayed secret scope,
  member refusal, replay refusal, unavailable rollout and mobile overflow. Three
  deliberate mutations were caught by assertions: retained MFA input, a late secret
  displayed across workspace switch, and secret persistence in localStorage.
- PostgreSQL owner/app-role operations regression: 30 tests passed. Final exact-source
  `npm run check` passed with 801 tests and 3 skips; the four browser workflows
  also passed after all modal/loading refinements. `npm audit --audit-level=high`
  reported zero vulnerabilities. Local runtime:
  Node 24.19.0/npm 11.9.0, Chromium; CI uses Node 22 and managed Chromium.
- Rollout/user guide: [operations-dashboard.md](../deploy/operations-dashboard.md).
  GitHub continuation checkpoint is also recorded in PR #25
  (comment 6277627115). Do not treat that provisional comment as deployment evidence.
- Before resuming: inspect git status and this entry, confirm final browser/check results, run `npm run check` and applicable regression checks, publish a PR containing
  this checkpoint, then observe CI and deployment. Record exact evidence, not intent.
- Next backend task remains OPS-004 below. No ingestion, health, incidents, live app
  credentials, provider onboarding or external witness was implemented by this UI work.

## Next action: OPS-004

Implement durable event ingestion using the accepted strict version-1 schemas and
`CredentialService.withCredential` to authorize and write in one committed transaction.
Derive scope/provenance from the credential, reject all body scope overrides, validate
component ancestry, canonicalize validated events and deduplicate across rotation.
Implement atomic batch receipts, clock windows, request/event/storage quotas, bounded
retention and counters. Do not use the lossy telemetry buffer or change browser events.
Preserve the organization-first anchor and use the same transaction connection; the
callback must be retry-safe and have no external side effects. Add real HTTP collector
race/DB failure/conflict/PII tests, memory/PG contracts, app-role grants, mutation and
contention/retention evidence. Do not infer ingestion readiness from credential tests.

OPS-002/003 prerequisites are already merged and enabled. Finish publishing the
dashboard slice above through normal CI first, then start OPS-004 from that baseline.
Local ingestion work needs no production token, external account or real alert destination.

## OPS-003 implementation entry

- **Task/state:** credential management and transaction-bound verification implemented;
  no production enablement and no collector route.
- **Commit/PR:** [PR #24](https://github.com/baimasonga/security-system/pull/24), initial implementation
  commit `9f71e7d`, stacked on PR #23. GitHub CI is separate from the local evidence below.
- **Behavior:** four management operations, separate admin/owner-only permission, real
  AuthService step-up, live-session recheck, reviewed reasons, one-time no-store secret
  response, explicit metadata projection and silent raw request logs. Secrets are 256-bit
  CSPRNG values; storage holds SHA-256 digests and 128-bit public IDs. Unknown IDs use a
  dummy fixed-size digest and secret comparisons use timingSafeEqual.
- **Lifecycle:** TTL 1–90 days, two active keys/environment/purpose, expiry may only shorten,
  overlap 0–3600 seconds, no repeated predecessor rotation or new rotation while an
  overlap predecessor is active. Zero-overlap replacement of one of two independent
  credentials preserves the cap. Revocation is irreversible, idempotent and audited once;
  it requires fresh MFA but remains possible during freeze/disabled/archived ancestry.
- **Persistence/boundary:** migration `0018_operations_credentials`, composite ancestor FK,
  immutable lifecycle trigger, no delete grants, shared memory/PG contract and organization
  lock. Role/session checks inside mutations use that connection. MFA consumption precedes
  the operations transaction and is not restored on later conflict/audit/commit failure.
  `withCredential` rechecks current scope, purpose, source, ancestors, enablement and expiry
  around a retry-safe callback/commit; OPS-004 must use it without caching detached authority.
- **Verification:** `npm run check` passed: 801 tests passed, 3 skipped. Full `npm run test:db`
  passed: 644 tests across 59 files (435.77 s), including the least-privilege app role.
  A final current-source credential-only PG/app-role replay passed all 18 checks. Twelve
  deliberate mutations caught MFA, secret comparison, environment scope, revocation, expiry,
  freeze, TTL, overlap, ancestor, audit, active cap and live-session bypasses. Tests cover
  secret-free metadata/logs/raw DB rows, OTP/recovery-code misuse, tenant/role/refusal and
  failed issue/rotate/revoke rollback. Node 24.19.0, npm 11.9.0, PostgreSQL 17; managed Linux.
- **Contention:** real HTTP/PostgreSQL, fsync on, three distinct MFA admins: first issuance
  exactly 2 creates + 1 conflict; competing rotation exactly 1 create + 2 conflicts;
  another rotation during overlap conflicts; a guarded callback commits before waiting
  revoke, then the revoked token fails. Four credential rows, eight credential audit events,
  no DB plaintext and a verified audit chain. The final replay passed with three contenders and two connections,
  confirming locked checks do not depend on an outer-pool connection.
  Inventory regression: 264 requests, 220 creates + 1 update + 43 expected conflicts,
  exactly 221 audit rows, verified chain, 2274 ms (previous OPS-002 run 1975 ms).
  `npm audit --audit-level=high`: zero vulnerabilities. Full database suite used the
  throwaway harness default (fsync off); both contention scenarios required fsync on.
  These short contention samples establish correctness, not sustained capacity or a measured
  latency regression; the historical V1 licensing benchmark is a different workload.
- **Configuration:** flags/MFA keys and tokens only in local fixtures; no production migration,
  secret issuance, application connection, notification or provider configuration.
- **Rollback:** disable credential flag, keep digests/history/audit; verifier refuses while
  disabled. Unrevoked/unexpired keys can work again after re-enable. See the
  [credential rollout/rollback guide](../deploy/operations-credentials.md).
- **Next:** OPS-004 as above. Credentials cannot grant commercial access or infrastructure authority.

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
