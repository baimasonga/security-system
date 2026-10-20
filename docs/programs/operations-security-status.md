# Operations/security implementation status and agent handoff

Updated: 20 October 2026.

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
Manual incident triage is implemented in the OPS-006 first slice below; automatic alerts and a live Rokela PDF monitoring integration remain pending. Ingestion was enabled in production on 20 October; authenticated source acceptance remains pending.

| Task    | State                                 | Verification/evidence                                                                                                                          |
| ------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below.   |
| OPS-002 | Production API/dashboard enabled      | Inventory API, store contracts, PostgreSQL migration/grants, safe errors, atomic audit and opt-in rollout.                                     |
| OPS-003 | Production API/dashboard enabled      | Scoped secrets, fresh MFA, rotation/revoke, guarded transaction verification and digest-only storage.                                          |
| OPS-004 | Implemented; local verification       | Strict committed ingestion, scoped deduplication, quotas, aggregates and bounded retention; evidence below.                                    |
| OPS-005 | Implemented; local verification       | Ordered heartbeat state, dependency health, scoped hourly history, persistence readiness and dashboard panels; network probes remain disabled. |
| OPS-006 | Manual triage slice; in progress      | Audited open/assign/acknowledge/resolve and dashboard controls; rules/outbox remain pending.                                                   |
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
- Verification: `npm run check` passed **845 tests, 3 skipped**. Full PostgreSQL
  owner/app-role regression passed **678 tests in 65 files** (345.13 s); final
  health/event PG replay passed **26 tests**, and migration replay passed **14**.
  Existing occupied-port child errors are intentional negative-path probes.
- All **four browser workflows** passed under Chromium/CSP. Fifteen deliberate
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
- Publication: implementation [`29a2cab`](https://github.com/baimasonga/security-system/commit/29a2cabe46aef0a52c133d2ebabf6477c7cef82b),
  [PR #29](https://github.com/baimasonga/security-system/pull/29), branch
  `codex/ops005-health`. Remote CI is recorded on the PR; production health
  rollout remains unverified here.
- Next: OPS-006 typed incidents, maintenance suppression and fenced notification
  delivery, using fake/local recipients; preserve the explicit external-monitor gate.

- Initial PR CI secret scan flagged the malformed `ops_v1.invalid` negative-path
  fixture. Added only its exact historical commit/file/rule/line fingerprint to
  `.gitleaksignore`; no real credential or broad rule/path suppression is involved.

- Follow-up readiness review removed repeated timeout handlers on a wedged query:
  callers now share the same settled timeout result until persistence completes.
  A fake-clock regression proves no new timers or queries appear after cache expiry.

- Readiness cache expiry uses monotonic time. A regression rolls wall time backward
  after cache expiry and confirms a new failed persistence check cannot reuse ready.

## Historical CI failures and assertion timing — 20 October 2026

The supplied Actions screenshot shows historical default-branch failures, not the
latest merged build. On merged `0f35a30`, [CI #89](https://github.com/baimasonga/security-system/actions/runs/39341881603)
and [CodeQL #91](https://github.com/baimasonga/security-system/actions/runs/39341881609)
both passed, including PostgreSQL, browser and Windows checks.

- [CI #85](https://github.com/baimasonga/security-system/actions/runs/39336192159)
  on `381a31b` failed the passkey clone test: sign-in was correctly refused, but
  the immediate database query raced asynchronous security-signal persistence.
  The test now polls for the same required signal with a five-second bound.
- [CI #84](https://github.com/baimasonga/security-system/actions/runs/39330159017)
  on `b5da658` inspected checked dependency options before the component form
  finished rendering. The browser test now polls for the same exact selected
  dependency list, independently of the later history-panel assertion.
- Controlled 50 ms signal/fetch delays exercise the asynchronous boundaries.
  In an isolated source copy, restoring either old immediate assertion fails
  with AssertionError; the fixed tests pass. No production delivery/authentication
  behavior, dependency persistence, test retry count or required assertion changed.
- Verification: passkey unit **10 passed**, PostgreSQL owner/app-role **20 passed**,
  browser **4 passed**, full `npm run check` **845 passed, 3 skipped**.
- Publication: implementation `1fd6ba6`, [PR #30](https://github.com/baimasonga/security-system/pull/30),
  branch `codex/ci-async-assertions`, based on merged `0f35a30`. Remote verification
  is recorded on the PR. OPS-006 remains the next feature task.

## Security Center controls — 20 October 2026

- User review found Security Center was a text-only summary. Added direct controls
  for email verification, authenticator enrollment/disable, passkey registration/
  removal, own-device deactivation with confirmation/offline-lease warning, refresh
  and sign-out. Organization cards open the correct workspace; monitoring controls
  are shown only for `ops:read` roles. Existing APIs remain the authority.
- Reused account forms keep the Security Center context for passkey changes. Pending
  protection responses are scoped to the initiating session/view; a late enrollment
  response cannot expose recovery codes after navigation or sign-out. No new endpoint,
  permission, migration, provider destination or production configuration was added.
- Implementation guide: [Security Center controls](../deploy/security-center.md).
  This UI work does
  not resolve the independent health clock-rollback/reactivation review findings or
  establish production health enablement/independent monitoring. Resolve those
  freshness findings before treating health as a reliable OPS-006 incident input.
- Verification: full `npm run check` passed **845 tests, 3 skipped**, including
  format, lint/boundaries and types. Chromium passed **8 browser workflows**:
  four existing operations flows plus real MFA enable/disable and fake email,
  virtual WebAuthn registration/removal, own-device confirmation/deactivation and
  workspace selection/member restrictions, and delayed recovery-code isolation.
- The existing MFA/passkey/privacy/device-trust suites passed **52 PostgreSQL
  tests in 8 files**, covering owner and restricted application-role behavior
  (23.95 seconds). No database/locking/retention change requires a new load test.
- TDD: the three action workflows first failed against the old text-only page.
  The delayed-response regression exposed an existing recovery-code display after
  navigation; the view/session guard fixes it. Deliberately removing that guard
  in `/tmp/security-center-mutation` failed with AssertionError; the original source
  remained unchanged. Browser and database work used local synthetic fixtures only.
- Evidence: `/tmp/security-center-check.log`, `/tmp/security-center-browser-final.log`,
  `/tmp/security-center-pg.log`, `/tmp/security-center-red-permitted.log`,
  `/tmp/security-center-late-red.log` and `/tmp/security-center-mutation.log`.
  Runtime: Node 24.19.0/npm 11.9.0/system Chromium. The cloud sandbox required
  loopback permission for local test servers; the permitted runs completed above.
  Production deployment and authenticated live acceptance remain unverified.
- Source: implementation [`15f7d41`](https://github.com/baimasonga/security-system/commit/15f7d41a66f52c4a4b7b47faab796935d8df55d3),
  branch `codex/security-center-actions`, based on merged `e597dc9`.
  Next: verify the deployed Security Center against a test account without sending
  real mail; keep production health rollout and OPS-006 gated on the recorded
  freshness corrections and independent-monitor acceptance.

## Security Center information hierarchy correction — 20 October 2026

- Follow-up screenshots showed that expanded privacy and permission descriptions
  still dominated the page. The earlier deployment-label interpretation did not
  establish the user experience. Network access now works: the public `portal.mjs`
  was byte-identical to `b58b74e` (SHA256
  `6af50cc5bb5e8378b62f35fdcaa6b022f25fcc9e75cb74b1b5bad29394710bad`).
  GitHub also reported Railway success for that exact commit. This confirmed the
  need to correct the default interface rather than assuming the old source served.
- Put account/email, authenticator and passkey controls together with explicit
  availability/attention states; own-device actions now precede organization cards.
  Monitoring/organization buttons stay visible. Account details, recommendations,
  role permission tables and privacy/retention descriptions use native collapsed
  disclosures. Keyboard users can open the information; mobile stacks the controls.
- Verification: full `npm run check` passed **845 tests, 3 skipped**; Chromium passed
  **9 workflows**, including the new default-state/keyboard/mobile regression and
  the existing real account/device/security actions. The new test failed against
  the previous layout before implementation. Screenshots use synthetic local
  accounts: `/workspace/scratch/security-center-desktop.png` and
  `/workspace/scratch/security-center-mobile.png`. Optional artifact output uses
  `SECURITY_CENTER_SCREENSHOTS`; CI has no hard-coded artifact filesystem dependency.
- Logs: `/tmp/security-layout-red.log`, `/tmp/security-layout-browser.log` and
  `/tmp/security-layout-check-final.log`. The first typecheck exposed DOM globals
  in a Node-typed browser test; switched to the existing browser-expression style
  and the complete check passed. This correction changes UI structure/styles only;
  no API, permission, database or transaction boundary changed, so no additional
  PostgreSQL/load/mutation scenario applies.
- Live public checks: `/healthz` returned `{"status":"ok"}`; authentication options
  reported email recovery configured and passkeys unconfigured. Passkey capability
  remains an explicit deployment prerequisite; no provider mail, production device
  mutation or authenticated production acceptance was performed. Health freshness
  findings and independent-monitor/OPS-006 gates remain open.
- Source: [`7b65ead`](https://github.com/baimasonga/security-system/commit/7b65ead)
  on `codex/security-center-actions`, based on `b58b74e`. After publication, compare
  public `/portal.mjs` and `/portal.css` with this source and inspect the exact-head
  Railway status; a successful push alone does not establish the corrected UI is live.
- Production verification completed: Railway reported success for exact source
  `ae3bc2a1c0cbb644306a8d7607f0e2d47ea57e02`. Public `/portal.mjs` and `/portal.css`
  both matched the tested correction byte-for-byte (SHA256
  `632e2af9d8bfe3bc79075e27f277735231dd33c2f533999ef75c0e27136e73dc` and
  `9e5999c4c10df6029614f8d41def2c179c117e7d6eabb71296b35fe6b1feb16c`).
  This establishes delivery of the corrected assets; account mutations were tested
  locally with synthetic fixtures, not against a real production account/provider.

## Feature activation and health freshness hardening — 20 October 2026

- User authorized production activation and separately approved private storage and
  a private malware scanner. Existing licensing, MFA and signing keys are preserved.
  Passkey RP configuration and durable ingestion are enabled; public auth options
  now report passkeys configured. API deployment
  `e16290c9-f31d-4c02-a1d6-d4a74795155f` reached SUCCESS; readiness returned 200.
  No real mail, payment, source credential or production device mutation was used.
- Closed the two OPS-005 review findings before enabling health: snapshots persist
  a per-organization monotonic observed time so a backward clock change cannot
  revive an expired heartbeat, including across service reconstruction. A heartbeat
  must follow the application, environment and component's current inventory epoch;
  disabling/re-enabling a parent cannot revive its old report. Updated rows require
  a strictly later timestamp; an equal timestamp remains conservatively unknown.
- Migration 0021 adds the finite timestamp and database regression guard. The
  existing account UPDATE grant applies; no new application privilege is required.
  Transaction snapshots clone/commit the memory watermark. ADR-029 and deployment
  guidance describe persistence, lifecycle semantics and forward-clock limitations.
- Verification: the new regressions failed before implementation. Full
  `npm run check` passed **848 tests, 3 skipped**; PostgreSQL owner/app-role suites
  passed **686 tests in 65 files**; Chromium passed **9 workflows**. Eight deliberate
  freshness-control mutations were killed by assertions in a disposable source copy.
  Real HTTP/PostgreSQL pool-2 load correctness passed: 1101 stored, 19 duplicates,
  1 conflict, 2 quota refusals; retention 1000/101/0, 678216 bytes released, zero
  remaining raw events, aggregates 1101→0 and verified audit chain. Twenty concurrent
  health reads and the 180-second stale transition passed (2840 ms scenario).
  This is correctness evidence, not a production capacity benchmark.
- Local evidence: `/tmp/activation-health-{red,unit,pg-targeted,check,pg-full,browser,load,mutations}.log`.
  Source is on `codex/feature-activation`, based on `0adb67a`; publication and live
  migration/health acceptance are recorded separately after deployment.
- Private ClamAV service reached SUCCESS and loaded its signature database; it has
  no public service domain. The approved private bucket was deployed from the two
  staged creation/region changes. Existing project authentication can read its
  connection settings; an additional Railway API token is unnecessary. No storage
  credentials or private access URLs are retained here.
- Remaining activation gates: verify private S3 operations/CORS and scanner clean/
  malware handling before claiming Files & links functional. The cloud environment
  draft adds the exact S3 endpoint for that test; publication is pending. Health
  activation is recorded below. Billing needs actual
  Paddle provider configuration; external audit witnessing needs an independent
  witness. Dual-control enforcement needs known enrolled approvers. OPS-006/007/008
  remain implementation work, not features that can be enabled with a flag.
- Next: publish this verified source, confirm migration/grants/readiness, enable
  health, complete private sharing acceptance, then start the first ready OPS-006
  task. Do not treat enabled routes as proof of authenticated live integration.

### Production health activation evidence

- Published [`af29522`](https://github.com/baimasonga/security-system/commit/af29522)
  to the existing default branch and `codex/feature-activation` after the final full
  check passed (848 tests, 3 skipped). No other checkout's unfinished work was pushed.
- Source deployment `1b4e2ade-4b51-4bd3-b36f-0ab37c04c9fc` reached SUCCESS.
  Deployment logs confirmed migration 0021; the configured pre-deploy command runs
  migrations, grants and database-profile verification before startup. Public
  `/readyz` and `/healthz` both returned 200 before activation.
- Set `OPERATIONS_HEALTH_ENABLED=true`. Configuration deployment
  `4fa6cea7-06a1-459c-9163-87cd073e90e1` reached SUCCESS. Production settings now
  enable inventory, credentials, ingestion and health independently. Public auth
  options report passkeys configured. These checks establish deployed configuration
  and readiness, not authenticated heartbeat/health acceptance or a live Rokela
  integration. Applications → environment exposes reported health when signed in.
- Private storage remains pending connection acceptance: the cloud runtime's current
  enforced policy does not yet include the saved S3 endpoint addition. A synthetic
  multipart/private-access/CORS/cleanup check has been prepared outside the checkout
  and has not run; no production sharing setting has been enabled prematurely.
  Publish the environment draft's endpoint addition and remove its unnecessary
  `RAILWAY_API_TOKEN` requirement; do not supply another token. Then resume sharing
  configuration and clean/malware acceptance. No new paid resources are needed.

## Railway private storage compatibility — 20 October 2026

- After the user published endpoint access, a real synthetic multipart upload
  reached the approved bucket but completion returned InvalidPart. The provider's
  ListParts response encodes ETag quotes as numeric XML entities; the adapter
  decoded only named entities and then filtered the opaque value, corrupting it.
  Fixed one-pass entity decoding and escaped completion XML without changing
  the ETag value. Added decimal/hexadecimal regression and XML-injection checks.
- The recommended provider addressing is virtual-host. Added bucket-qualified
  endpoint support, preserving path-style behavior for existing endpoints and
  checking a similar-prefix hostname does not select virtual-host addressing.
  Both presigned and server requests keep their configured host; redirects remain
  forbidden. No credentials, share URLs, database changes or new resources are
  introduced by this source correction.
- TDD: two ETag regressions and the virtual-host regression failed before their
  fixes. All eight S3 adapter tests pass. Three deliberate mutations (numeric
  decoder removal, XML escape removal, virtual-host bypass) were killed by
  assertions; source was restored after each.
- Live shared-endpoint acceptance: multipart create/upload/list/complete/read
  passed with the ETag fix, anonymous object access was denied, and synthetic
  objects/multipart uploads were removed. The exact portal-only CORS policy was
  stored and read back successfully, but actual shared-endpoint upload/preflight
  responses returned wildcard CORS. This does not establish browser-origin
  acceptance. No production sharing setting was enabled on that evidence.
- Saved one additional exact bucket-host network destination for the provider's
  recommended endpoint. Publication and virtual-host CORS acceptance are pending.
  Existing Railway project authentication suffices; no additional token is needed.
- Next: verify the recommended endpoint after publication, deploy this correction,
  then wire approved storage/private ClamAV settings and test clean/rejected-file
  behavior. Record full check/PostgreSQL results below before source publication.

- Verification completed before publication: full `npm run check` passed **852
  tests, 3 skipped**; targeted sharing/security PostgreSQL suites passed **54 tests
  in 4 files**, covering owner and least-privilege app roles. The first PG attempt
  failed because the disposable local database was stopped; after restarting the
  existing container the suites passed. No production database was used.
  Logs: `/tmp/sharing-etag-red.log`, `/tmp/sharing-virtual-host-red.log`,
  `/tmp/sharing-compat-check.log`, `/tmp/sharing-compat-pg.log`. The source correction
  changes object-store wire compatibility only; no transaction, retention, quota,
  locking or schema behavior changed, so a new database load scenario is not
  applicable. Production upload quarantine/scanner acceptance remains pending.

## Files & links production activation — 20 October 2026

- Published endpoint access became active in the running cloud session (enforced
  policy revision 5). The provider-recommended bucket-qualified endpoint passed
  real multipart create/upload/list/complete/read, anonymous object-access denial,
  and synthetic object/multipart cleanup. Stored and actual upload/preflight CORS
  both allow the exact portal origin and expose ETag. The shared-endpoint wildcard
  finding does not apply to the recommended endpoint used in production.
- Storage compatibility source `39a178c` deployed successfully as
  `b558f024-a783-48f4-ae35-9c5fb3ad353a`. Configured the existing API service with
  approved private S3 storage and private ClamAV on port 3310. Generated a dedicated
  sharing secret only because none existed; preserved all existing identity,
  licensing, MFA and signing secrets. Malware scanning remains required. The
  scanner has no public service domain. Connection values are not retained here.
- Sharing configuration deployment `0ccc3d36-5cbe-4f54-9260-171ae3164715` reached
  SUCCESS. Public readiness and health both returned 200. Authenticated production
  acceptance with isolated synthetic accounts passed: Files & links overview,
  temporary transfer creation, signed multipart uploads, clean PDF quarantine
  through the configured scanner, EICAR rejection/removal, exact clean download
  contents and denial of a download URL for the rejected file. No paid entitlement
  was fabricated and no provider mail or payment was initiated.
- The first acceptance probe timed out because it expected a durable `rejected`
  status: cleanup had already moved EICAR to `deleted`. The corrected probe accepts
  either state only with the persisted `malware_signature` rejection reason, and
  then verifies download refusal. Final run passed. Both synthetic transfers were
  deleted through the API and background object deletion queued; sessions logged
  out. Synthetic account/audit records remain, with no elevated privileges.
  Evidence: `/tmp/live-sharing-acceptance.log` and
  `/tmp/live-sharing-acceptance-final.log`; helpers outside the checkout retain no
  credential values or private URLs. Public accounts/providers were not exercised.
- A separate provider-level two-day incomplete-multipart lifecycle policy could
  not be installed: the bucket returned an empty lifecycle configuration, then
  rejected the standard cleanup rule. Existing lifecycle rules were not replaced
  and no complete-object expiration was requested. Application abandoned-upload
  retention/abort and deletion jobs remain enabled; independent provider lifecycle
  cleanup remains an operational follow-up, not a verified capability.
- Enabled and deployed: inventory, credential management, durable ingestion, health,
  passkey configuration and Files & links. Existing plan/RBAC gates still apply.
  Billing provider setup, independent audit witnessing, enrolled dual-control
  approvers and authenticated operations-source integration retain their earlier
  acceptance limits. Next implementation task remains OPS-006; OPS-007/008 are
  pending and must not be described as activated features.

## OPS-006 first vertical slice — manual incident triage, 20 October 2026

- Based on deployed `330842b`, implemented a separately gated human incident
  workflow: open for an active component, assign/unassign an active same-org
  responder, acknowledge and resolve. Source is always `manual_triage`, not a
  backend assertion or independent probe. Owners/admins get the explicit
  `ops:manage_incidents` permission; members and integration keys do not.
- Memory/PostgreSQL adapters share an incident contract. Migration 0022 adds
  ancestor foreign keys, single-active manual incident index, finite timestamps,
  immutable creation/scope/severity, monotonic versions and terminal resolution.
  App-role grants are SELECT/INSERT/UPDATE; no delete/truncate. Serialized org
  transactions recheck authorization/session/freeze, validate assignment, and
  commit state plus mandatory reason audit together. Audit failure rolls back.
- Strict live OpenAPI and routes expose bounded list/open/assign/acknowledge/resolve
  operations. Scope errors are 404; stale edits 409; unknown/private fields rejected.
  A 1000-retained-record environment cap refuses another open without deleting
  evidence. No automatic retention/pruning claim is made. Ancestor deactivation
  prevents new incidents but allows responders to close existing work.
- Applications → environment now contains an actionable Incidents panel with open,
  assignment, acknowledgement and resolution forms, current versions and paginated
  rows. Late responses after navigation cannot reopen an abandoned workspace.
  Stale-edit messaging does not demand an MFA factor for incident actions.
- Contract/ADR/threat model and `docs/deploy/operations-incidents.md` describe the
  slice, rollout and rollback. Source `OPERATIONS_INCIDENTS_ENABLED` defaults false
  and requires inventory; no new secret/provider or paid resource is required.
- Local browser acceptance passed **11 workflows** including the new incident
  lifecycle and late-response regression. Targeted owner/app-role PostgreSQL
  verification passed **42 tests in 5 files**. The first database attempt started
  before PostgreSQL was ready; after startup the suites passed.
- Real HTTP, fsync-on disposable PostgreSQL, pool 2 contention correctness passed:
  20 opens → one creation; 20 competing acknowledgements → one success and 19 stale
  refusals; 20 concurrent reads succeeded; resolution followed by a new manual open
  retained exactly two rows and four incident audit events, with verified audit
  chain. Initial duration 936 ms; this is not a capacity benchmark.
- Evidence: `/tmp/incidents-red.log`, `/tmp/incidents-unit.log`,
  `/tmp/incidents-pg-targeted.log`, `/tmp/incidents-browser-final.log`,
  `/tmp/incidents-load.log`, `/tmp/incidents-mutations.log`,
  `/tmp/incidents-pg-full.log` and `/tmp/incidents-check-final.log`. Full-suite and
  mutation outcomes, source publication and live activation are recorded below
  after completion; the presence of these paths alone is not passing evidence.
- OPS-006 remains incomplete: typed automatic rules/evaluation windows, maintenance
  suppression, fenced notification outbox/retries/visible failures, incident pruning
  and delivery-outage acceptance remain. No real alerts were sent. Next: implement
  automatic rule evaluation against durable evidence with fake notification
  recipients before enabling delivery or starting the OPS-007 incident integration.

### Local verification completed

- Full `npm run check`: **859 passed, 3 skipped**. Full PostgreSQL owner/app-role
  suite: **694 passed in 67 files**, 385.75 seconds. Expected child-process occupied-
  port failures appeared in the negative load-server probes; the suite passed.
  Final incident PG/audit-payload rerun: **28 passed in 4 files**.
- Chromium: **11 passed**, including open/assign/acknowledge/resolve and the delayed
  mutation/navigation regression. **20 mutations killed by assertions**, including
  authorization/session/freeze, omitted audit intent, wrong assignee membership,
  version/terminal guards, inactive ancestry, duplicate opens, quota, backward clock,
  memory transaction clone/commit, member privilege escalation, PostgreSQL scope,
  terminal guard/unique index, and late browser responses. All disposable source
  mutations were restored and their copy removed. An initially surviving omitted-
  audit mutation exposed a test gap; added explicit successful-transition audit
  assertions before the complete passing mutation run.
- Assignment audit records preserve previous/new responder IDs and state; the final
  targeted unit/API run passed **7 tests**, and final PG verification passed above.
  No secret, private link, customer event payload or file content is in these records.
- Publication baseline: `330842b`; implementation branch
  `codex/manual-incident-triage`. Production rollout/acceptance is recorded separately
  after migration, grants and source deployment complete.
