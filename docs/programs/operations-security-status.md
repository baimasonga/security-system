# Operations/security implementation status and agent handoff

Updated: 19 October 2026.

## Current state

OPS-001 design, OPS-002 inventory, OPS-003 credential management and their dashboard
controls are implemented. Inventory and credentials default off in source but are
both enabled in the existing Warrior Railway production service. Open **Applications**
in the signed-in portal; owners/admins can manage applications, environments,
components/dependencies and fresh-MFA credentials without constructing API calls.

OPS-002/003 merged in PR #24 (`919dff77`); dashboard PR #28 merged as `05e58fa8`.
PRs #23 and #25 were closed as superseded; their implementation/evidence is retained.
Dashboard deployment `3d2dd35a-cff8-4b24-8762-a72e7a554a3b` reached SUCCESS.
Credential verification remains a guarded transaction primitive, not a collector.
OPS-004 durable ingestion is now implemented behind `OPERATIONS_INGESTION_ENABLED`
(default false); verification is recorded below. Health/history reads are now implemented behind default-off `OPERATIONS_HEALTH_ENABLED`.
Incidents and a live Rokela PDF monitoring integration remain pending. No ingestion production setting was changed.

| Task    | State                                 | Verification/evidence                                                                                                                          |
| ------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below.   |
| OPS-002 | Production API/dashboard enabled      | Inventory API, store contracts, PostgreSQL migration/grants, safe errors, atomic audit and opt-in rollout.                                     |
| OPS-003 | Production API/dashboard enabled      | Scoped secrets, fresh MFA, rotation/revoke, guarded transaction verification and digest-only storage.                                          |
| OPS-004 | Implemented; local verification       | Strict committed ingestion, scoped deduplication, quotas, aggregates and bounded retention; evidence below.                                    |
| OPS-005 | Implemented; local verification       | Ordered heartbeat state, dependency health, scoped hourly history, persistence readiness and dashboard panels; network probes remain disabled. |
| OPS-006 | Not started; depends on OPS-004/005   | Incident/notification design only.                                                                                                             |
| OPS-007 | Not started; depends on OPS-004/006   | Rokela PDF brief aligned with accepted event contract; no live connection.                                                                     |
| OPS-008 | Not started; depends on OPS-006       | Existing recovery runbook is not restore evidence.                                                                                             |

## Initial backend enablement — 19 October 2026 (historical)

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
  At this initial rollout, management required the documented APIs; the dashboard
  release below subsequently closed that UI gap. Events, health, incidents and live Rokela PDF
  integration remain unimplemented. Existing external audit anchoring remains disabled.
- Rollback: disable credentials first, then inventory if required; keep migrations,
  stored digests and audit history. Do not replace the MFA key or licensing secrets.

## Dashboard release and next-agent handoff — 19 October 2026

User authorized making the implemented APIs usable from the dashboard and requested
this durable handoff. Resume from the current default branch
`claude/sleepy-carson-l0if1k`, not an older feature checkout. Read AGENTS.md/CLAUDE.md,
this file and the accepted operations contract before changing the next task.

### Shipped behavior and evidence

- **Source:** [PR #28](https://github.com/baimasonga/security-system/pull/28),
  implementation `e522703`; integrated default-branch compatibility PR #26 (`5f89809`)
  without conflicts. Exact checked head `8140729`, merged source
  `05e58fa8c67fa78b047aa5ba3a6fbb45eeb36860`.
- **UI:** Applications navigation, nested inventory registration/read/edit, owner,
  criticality and optional licensing Product mapping, same-environment dependencies,
  expected-version lifecycle mutations, retained archive lookup, and fresh-MFA
  credential issue/rotate/revoke. Disabled/archived parents preserve emergency revoke.
  Product mapping still grants no commercial authority. Backend RBAC/schema unchanged.
- **Browser boundary:** captured organization/visit scope, old-session 401 isolation,
  factors cleared before requests, no persistent browser secret storage, one-time
  modal cleared on close/cancel/navigation/pagehide, late secrets suppressed across
  workspace changes, and existing select/dependency/Product values preserved.
- **Local verification:** final integrated `npm run check`: **802 passed, 3 skipped**;
  four real browser/API workflows pass under CSP. PostgreSQL owner/app-role inventory
  and credential regression: **30 passed**. Three deliberate mutations were caught by
  assertions: retained MFA input, cross-workspace late secret, and localStorage secret
  persistence. `npm audit --audit-level=high`: **zero vulnerabilities**. Local Node
  24.19.0/npm 11.9.0; CI uses Node 22 and downloaded Chromium.
- **CI:** all eight exact-head checks passed, including the new browser job, full
  owner/app-role PostgreSQL suite plus load smokes, Windows SDK, dependency/secret
  scanning and CodeQL. CI run `39328226017`; CodeQL run `39328226005`.
- **Production:** existing project `victorious-commitment` / service
  `@trust/platform-api`; deployment `3d2dd35a-cff8-4b24-8762-a72e7a554a3b`
  reached SUCCESS on merged source `05e58fa8`. Logs confirm migrations through 0018,
  verified database TLS and API startup. No MFA/signing/licensing secret was replaced,
  no production integration credential was issued, and no real notification was sent.
- **Deploy fix:** automatic and explicit deployments were SKIPPED with the build log
  `no changes detected in watch paths`. Widening the filter (`/**`, then `**`) did not
  solve it. Removed the service watch-path filter entirely (all-source default),
  retained the same repository/default branch with no commit pin, and explicitly
  deployed latest source. This triggered the successful Dockerfile build above.
  Do not reinstate the old filter without proving that changed code deploys.
- **Verification limits:** local public HTTP requests hit the managed outbound proxy's
  CONNECT 403; the remote public-reader tool also could not access this hostname.
  Browser workflows were verified locally and in CI, not using a production account.
  Railway SUCCESS/startup/health evidence establishes deployment, not authenticated
  production acceptance or a live monitoring integration.
- **Guide:** [operations-dashboard.md](../deploy/operations-dashboard.md).
  Final rollout/continuation evidence is also in PR #28's conversation
  (comment `6278048962`); PR #25's checkpoint `6277627115` points there.

### Continue here

1. Reconcile the current default branch before changing code; another account has
   been advancing it independently. The original local prototype remains preserved
   in `/workspace/security-system`; the accepted implementation is the upstream
   package architecture, not that old checkout's wire contracts.
2. OPS-004 is implemented in this change. Review its exact verification evidence
   below and keep ingestion disabled until its rollout gate is explicitly exercised.
3. Implement OPS-005 next. First amend the health contract to bound heartbeat
   occurrence age and order; receipt-time TTL alone must not let a queued old
   healthy observation override a later unavailable report. Add negative/mutation
   tests before the health state machine. Keep `/healthz` liveness separate from
   readiness and keep all network probes disabled.
4. Then implement OPS-006 incidents/notifications, OPS-007 Rokela PDF integration
   and OPS-008 security/recovery evidence in dependency order. Rokela PDF's source
   is `baimasonga/rokelapdf-online`, cloned locally, with no live monitoring setup.

### Other feature activation gates (not blockers for OPS-004 development)

- Passkeys need the permanent Warrior RP domain and HTTPS origin. Changing the RP
  domain later requires re-enrollment; choose it with the owner rather than guessing.
- Warrior file sharing/short links need their own private object-store and scanner
  configuration. Rokela PDF's working services/configuration are a separate deployment;
  do not assume they are automatically connected to Warrior or copy their secrets.
- External audit anchoring remains disabled. A real independent witness is required;
  a placeholder URL or this same database is not equivalent evidence.
- Privileged dual control needs two enrolled operators; do not turn it on blindly
  and strand the only operator. Keep existing licensing/customer access intact.
- Payment-provider onboarding/pricing and identity-provider SSO require owner/provider
  setup. Preserve the existing operator-managed plan decision and configuration-only
  SSO scope; do not silently switch paid-plan management or generate fake credentials.

## Next action: OPS-006

Implement incidents and notifications against the accepted typed-rule design. Specify
routes first, require current scoped authority and audited transitions, commit incident/
audit/notification intent atomically, and use fenced bounded delivery with fake/local
recipients. Add maintenance-window suppression without turning missing/stale observations
healthy. OPS-005 exposes backend assertions, not independent probe truth. Preserve existing
commercial access; live Rokela source delivery is OPS-007 and restore evidence is OPS-008.

The previous SDK review also identified a persisted-clock rollback gap in
`packages/sdk-core/src/updates.ts` (`verifyEvidence`, reviewed at `7ad2e6c`); it is
outside this ingestion change and remains a follow-up. The original reproduction
is `/tmp/review-update-clock.mjs`, with review evidence in
`/workspace/scratch/security-system-review-7ad2e6c.md`.

## OPS-003 local implementation entry (historical)

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

## OPS-004 durable ingestion implementation — 19 October 2026

- Implementation commit: [`74e708c`](https://github.com/baimasonga/security-system/commit/74e708c8e68ca924cbb03603fc8c21e19015e276), followed by this evidence-only publication entry.

- Baseline: `b5da658` (merged OPS-002/003, dashboard PR #28 and dependency fixes).
  The older local inventory/credential prototype is preserved and was not merged
  over the independent implementation. Source work is in
  `/workspace/security-system-current` on `codex/ops004-ingestion`.
- Behavior: integration-only `POST /v1/operations/events`, nine strict typed backend
  schemas, fixed privacy errors, credential-derived immutable provenance, current
  component scope/lifecycle checks, canonical content hashes and scoped UUID
  deduplication across rotation, original receipt preservation, atomic mixed batches,
  and acknowledgement only after the credential transaction commits.
- Budgets: per-key sliding sixty-second authenticated-request window (duplicates and client refusals count), UTC daily
  environment/org new-event limits, canonical bytes plus 512-byte accounting against
  environment/org storage caps. Request/day/storage counters, event rows and hourly
  component/type/outcome aggregates commit together under the existing organization
  anchor. No commercial quotas or global per-event audit appends are introduced.
- Retention: migration 0019 adds strict scoped provenance FKs and expiry indexes;
  app grants deny event UPDATE. The existing maintenance worker deletes at most
  1,000 event rows per org/pass, atomically releases exact storage counters, and
  expires request/day metadata and ninety-day aggregates in bounded batches.
  A pass visits at most 25 eligible organizations. Raw event/identity retention is
  thirty days; no exactly-once guarantee follows after expiry.
- HTTP/observability: 256 KiB body cap, identity encoding only, bounded pre-auth IP
  budget, silent raw request logs, safe status/receipt metrics with fixed labels,
  generic retryable 503 on collector failures, and Retry-After only on 429.
  Only implemented ingestion moved to live OpenAPI. Eight pre-existing flow-map
  response descriptions and a sharing tag required quoting for full schema validity;
  live reference/response-map regression coverage accompanies those repairs.
- Tests: shared memory/PG event store and committed-ingestion contracts cover
  rollback, withheld ACKs, ambiguous commit retries, concurrent duplicates and
  event-write/revocation ordering. HTTP tests exercise genuine issued credentials,
  session/license rejection, privacy/scope/version/body/encoding errors, feature
  disablement, quotas, safe outages and management-freeze ingestion.
- Verification failures and corrections: the first negative-only validator test
  also passed when the export was missing; added a positive control before building.
  App-role PG exposed a retention FOR UPDATE requiring excessive privilege; removed
  that redundant clause rather than allowing event rewrites. Outcome aggregation
  and fixture mistakes were caught by types/adapter tests and corrected.
- Verification: `npm run check` passed **832 tests, 3 skipped**; full
  `npm run test:db` passed **670 tests across 63 files**, including the
  least-privilege role (345.57 seconds). Both OpenAPI 3.1 documents validate with
  Swagger Parser 12; npm audit reports **zero vulnerabilities**. EADDRINUSE child
  errors in the PG log are expected occupied-port rejection probes, not failures.
- Eighteen deliberate mutations were killed by assertions in an isolated source
  copy, including schema/privacy boundaries, enum/integer checks, clock/scope/state,
  canonical identity, request/day/storage budgets, rejected-request metering,
  rollback, exact storage release and bounded deletion. Original bytes were restored.
  Authenticated client refusals commit only fixed request accounting; event/day/
  storage changes remain staged until all client-controlled validation succeeds.
- Real HTTP/PG contention and retention: pool 2, 20 contenders, one stored receipt
  and nineteen duplicates; 1,101 total event rows, one atomic conflict and two quota
  refusals; deletion batches 1,000/101/0 release exactly 678,216 bytes; ninety-day
  aggregates expire and the audit verifies. Final replay 3,172 ms including setup,
  alongside regression tests; this is correctness evidence, not capacity. See
  [collector performance note](../performance/operations-ops004.md).
- Evidence: `/tmp/ops4-complete-check.log`, `/tmp/ops4-final-full-pg.log`,
  `/tmp/ops4-mutations.log`, `/tmp/ops4-contention-final.log` and
  `/tmp/ops4-audit.log`. Verification used Node 24.19.0/npm 11.9.0 and local
  PostgreSQL 16 with synthetic fixtures and fsync on. No production ingestion flag,
  integration secret, real destination, application source outbox or live Rokela
  PDF connection was configured. Remote CI/deployment results are unverified.
- Rollback: disable `OPERATIONS_INGESTION_ENABLED`; retain additive schema, digests,
  history and ordinary retention. See [ingestion guide](../deploy/operations-ingestion.md).
- Next: OPS-005 with the health freshness/order amendment before implementation.

## OPS-005 takeover implementation — 19 October 2026

- Baseline `381a31b`, reconciled from the other Codex's published collector/handoff.
  Preserved the overlapping old checkout untouched; isolated worktree
  `/workspace/security-system-health`, branch `codex/ops005-health`.
- Latest eligible heartbeat metadata commits atomically with evidence; 120-second age
  bound, no future reports, occurrence ordering and conservative ties prevent queued
  recovery and receipt refresh. Snapshot TTL is 180 seconds, with explicit unknown/
  stale/inactive and dependency states. Migration 0020 adds bounded retained metadata.
- Live-session ops:read controls protect scoped health and hourly history. Read-only
  dashboard panels expose reported health and recent event counts with explicit gaps.
  Fixed internal persistence readiness is separate from process liveness.
- No production setting, live credential, provider destination or external monitor was
  configured. Optional-provider readiness, independent external Warrior monitoring,
  incident maintenance suppression and the live source integration remain explicit
  rollout/next-task requirements. See [health guide](../deploy/operations-health.md).
- Verification: `npm run check` passed **843 tests, 3 skipped**. Full PostgreSQL
  owner/app-role regression passed **678 tests in 65 files** (345.13 s); final
  health/event PG replay passed **22 tests**, and migration replay passed **14**.
  Existing occupied-port child errors are intentional negative-path probes.
- All **four browser workflows** passed under Chromium/CSP. Thirteen deliberate
  mutations were caught, including PostgreSQL ordering/scope; reproducible tool:
  `tools/mutation-check-operations-health.mjs` (disposable source copy).
- Real HTTP/fsync-on, pool=2 load retained all expected collector totals and
  verified **20 concurrent health snapshots** plus the **180-second stale boundary**.
  Total smoke time 7,678 ms alongside other suites; no capacity claim. See
  [OPS-005 performance note](../performance/operations-ops005.md). Dependency audit
  reports **zero vulnerabilities**. OpenAPI drift/reference checks passed.
- Validation caught an ambiguous browser selector after adding the second component
  table; scoped it to inventory. Mutation checks exposed overlapping history
  rejection predicates, so range and retention tests now exercise each independently.
- Publication: branch `codex/ops005-health`; implementation/PR reference follows
  publication. Remote CI and production health rollout remain unverified here.
- Next: OPS-006 typed incidents, maintenance suppression and fenced notification
  delivery, using fake/local recipients; preserve the explicit external-monitor gate.
