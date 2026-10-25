# Operations/security implementation status and agent handoff

## Restored authentication acceptance — 25 October 2026

- Extended the synthetic restore exercise to log in against the restored database
  and use its newly authenticated principal for the recovered application read.
  Previously that read reused the source database's principal.
- Incorrect passwords and accounts created after the snapshot must be rejected.
  Audit integrity is checked again after restored authentication operations.
- The isolated PostgreSQL 16/fsync-on exercise passed all 25 migration checks,
  restored login, both rejection cases, application read and audit verification.
- Updated the stale recovery runbook and added production rehearsal prerequisites,
  isolation of restored outboxes/credentials, matching-version validation, secret
  recovery, authority reconciliation and explicit RPO/RTO evidence requirements.
- Production backups/PITR and a real isolated production restore remain unverified.
  Next live step: identify an approved private restore destination and actual
  provider backup coverage; do not export production data into this workspace.

## Independent witness receiver implementation — 25 October 2026

- Implemented `tools/audit-witness` receiver/storage core and a separate AWS Lambda
  adapter, pinned SDK/bundler lockfile, CloudFormation template and build/acceptance
  guide in `infrastructure/audit-witness`. No cloud resource has been provisioned.
- Incoming requests require the dedicated bearer token, strict bounded manifests
  and the existing anchor digest. Canonical full manifests are conditionally created
  under content-derived keys. Success requires an exact version receipt and verified
  COMPLIANCE retention metadata. Retries and concurrent creates converge; earlier
  manifest objects remain separate from later observations.
- Default bucket retention avoids giving the receiver retention-edit permission.
  Template retains evidence on rollback, denies deletion/unconditional overwrite,
  blocks public access and limits route/rate/concurrency. Receipt version IDs are
  base64url encoded (S3 IDs may contain slash/plus); real audit shard IDs with `#`
  are accepted. Receiver has no database, identity, email or licensing access.
- Local tests cover receiver refusals, storage failures, retries, concurrent calls,
  template permissions, SDK command wiring, and tampered synthetic history checked
  against separately retained earlier evidence. Fake S3 tests are not proof of real
  AWS IAM/Object Lock enforcement. CloudFormation lint and bundle build passed;
  a built-handler smoke test rejects unauthorized requests without AWS access.
- Verification: `npm run check` passed 1126 tests (3 skipped), including 33 new
  receiver/storage/template tests. Five SDK-adapter tests pass. Seven deliberate
  mutations were caught (authentication, digest, body limit, safe integer, retention
  mode, exact version and conditional PUT), then restored and checks passed.
  CloudFormation lint passed, the Lambda bundle built, and its production dependency
  audit reported zero vulnerabilities. CI now runs adapter tests, bundle and audit.
- Remaining activation gate: select independent AWS account/region and explicitly
  approve retention, review a change set and costs, provision, run real-cloud denial /
  retrieval / retention acceptance, then configure Warrior and verify a publication
  independently. Existing disabled-anchoring warning must remain until acceptance.

## Audit verifier CA support — 24 October 2026

- Next independent prerequisite while live email acceptance is blocked: the offline
  verifier previously constructed a raw PostgreSQL pool, ignoring the provider CA
  configuration already supported by the application runtime.
- It now uses shared CA parsing and verified TLS pool settings, supports inline or
  file certificates, rejects unconfigured remote plaintext, and preserves local
  restore-fixture connections. Invalid TLS configuration exits 2 without creating
  the pool or echoing configuration values. No schema or audit verification algorithm
  changed; no production audit or credentials were modified.
- Added connection tests and an actual CLI negative-path test. Removing the CLI's
  CA wiring was caught by the subprocess test, then restored. `npm run check` passed
  1093 tests (3 skipped), including eight new verifier connection/CLI tests.
- External witness remains a prepared specification, not a provisioned independent
  receiver. No production manifest or tamper-evidence acceptance is claimed from
  these tests. Next: implement the receiver against the existing manifest contract
  with local storage-adapter tests before choosing/provisioning an independent account.

## Incident-email acceptance preparation — 24 October 2026

- Owner authorized continued unattended build/integration and an isolated opened /
  resolved email test. The Railway connector currently requires reauthentication;
  no deployed runtime or provider credentials are accessible through that connection.
- Read-only production counts confirm the owner exists, email is verified, eight
  rules are enabled, and notification counts are zero in all four states. No test
  message has been sent and no production inventory or rule was changed.
  Stored rule observations are healthy: three event-count, three heartbeat and two
  probe rules. These observations do not prove incident email delivery.
- Added deployment-local `tools/check-incident-email.ts`: validates actual runtime
  config, uses the application connection with configured CA, checks schema, reads
  only per-recipient verification/rule/notification aggregates in a read-only
  transaction, and emits fixed metadata. No account address or provider error is
  printed. It distinguishes email enablement from identity mail and refuses to call
  historical portal delivery proof of email delivery.
- Verification: `npm run check` passed 1085 tests (3 skipped). Seven new readiness
  tests cover each missing prerequisite, secret exclusion and delivery-evidence
  limits; bypassing the email flag was caught by a deliberate mutation, then restored.
  The six existing simulated email lifecycle tests passed. The aggregate SQL was
  independently executed read-only against production. Invalid CLI arguments exit 2
  with a fixed message and no database access.
- Local lifecycle tests use the existing fake provider; they do not establish real
  Cloudflare acceptance. Next live step: run the preflight inside the deployment,
  then the isolated acceptance procedure in the automation guide with authenticated
  inventory access and a fresh-MFA scoped credential. Preserve all eight live rules.
  Inbox acknowledgement remains necessary even after provider acceptance.

## AI-assisted investigation entry point — 24 October 2026

- Owner authorized the recommendation to start with read-only IT investigation and
  code review. Added an operator-run diagnostic brief and manual GitHub workflow,
  reusing the four fixed, bounded public checks for Warrior and Rokela PDF.
  No model service, remediation permission, database access or email send is added.
- [Investigation runbook](../runbooks/ai-assisted-investigation.md) records evidence
  handling, deployment correlation, tests, GitHub publication and live recovery checks.
  The brief explicitly leaves root cause and authenticated behavior unestablished.
- Baseline cfcc617 CI, CodeQL and release observation passed; recovery exercise
  40103008955 passed on 6e4afa0. Latest owner screenshots show verified email and MFA
  enabled, superseding the older unverified-account observation below. Incident email
  delivery, production restore acceptance and independent witness remain unverified.
- The workspace's public-check attempt returned four failures; restricted observer
  networking means this is not evidence of four production outages. Use the independent
  GitHub workflow to verify reachable public endpoints after publication.
- Verification: `npm run check` passed 1078 tests (3 skipped), including three new
  brief tests for fixed anonymous destinations, mixed outcomes, safe failure output
  and evidence limits. A deliberate false-root-cause mutation was rejected, restored
  and the new suite passed again. Manual workflow YAML parsed with read-only permissions.
  Full checks required network permission for existing local HTTP server tests.
- Next: run **Actions → IT incident brief → Run workflow** after publication and use
  its bounded report with the runbook. No live success, model integration or unattended
  remediation is claimed by the local tests.

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
Manual triage and the automatic failure/incident/recovery lifecycle are production accepted with synthetic sources. The Rokela PDF source adapter is locally verified and published; its real production binding remains pending. Ingestion is enabled in production; no live PDF source acceptance is claimed.

| Task    | State                                          | Verification/evidence                                                                                                                          |
| ------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 | Contract complete; local verification          | Accepted ADR-029/threat model, normative contract, separate planned OpenAPI, safe examples and 25 schema checks. Publication evidence below.   |
| OPS-002 | Production API/dashboard enabled               | Inventory API, store contracts, PostgreSQL migration/grants, safe errors, atomic audit and opt-in rollout.                                     |
| OPS-003 | Production API/dashboard enabled               | Scoped secrets, fresh MFA, rotation/revoke, guarded transaction verification and digest-only storage.                                          |
| OPS-004 | Production enabled; source acceptance pending  | Strict committed ingestion, scoped deduplication, quotas, aggregates and bounded retention; evidence below.                                    |
| OPS-005 | Production enabled; source acceptance pending  | Ordered heartbeat state, dependency health, scoped hourly history, persistence readiness and dashboard panels; network probes remain disabled. |
| OPS-006 | Production lifecycle and UI verified           | Audited manual/automatic incidents, typed rules, maintenance and fenced portal notifications; local acceptance below.                          |
| OPS-007 | Adapter locally verified; live binding pending | Private source outbox and real local failure/recovery acceptance; no production source connection.                                             |
| OPS-008 | Production enabled; synthetic API accepted     | Scoped scan/recovery imports and triage, bounded read-only GitHub collection and organization overview; evidence remains unverified.           |

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
  exactly 2 creates + 1 conflict; competing …17639 tokens truncated…e its Supabase Auth templates/SMTP/rate-limit settings,
  not Cloudflare transfer-mail settings. No publishable keys were logged.
- Synthetic posture acceptance helper is outside the checkout at
  `/workspace/scratch/verify-live-posture.py`: strict normalized import/dedup,
  assigned remediation, stale-version conflict, backup/restore separation,
  unverified provenance and synthetic inventory archival. It has not run against
  production because the new source is not deployed. Never describe these fixture
  report submissions as actual production restores.

- Exact source GitHub CI `39475473694`: source checks, browser workflows, Windows
  integration and dependency/secret scans passed; its PostgreSQL job was still
  running at handoff (local full PG already passed 725). CodeQL `39475473558`
  passed. PDF signup-guidance CI `39475312241` passed both source and converter
  jobs. A later deployment retry again returned Railway's temporary-pause refusal.

### Continuation — email handoff and GitHub collector, 20 October

- User authorized continuing Warrior implementation after the email work without
  further routine approvals. PDF source `234c3fb` adds a signed Cloudflare Supabase
  Send Email Hook with the actual logo, colors and ownership details. Local check
  passed 231 tests (2 skipped), production build and desktop/mobile email renders
  passed, and unsigned compiled-route requests were refused. No live email was
  sent. PDF Railway access remains unavailable and Supabase administrative access
  is absent, so the hook is not activated. Its CI source, app-role and production
  build checks passed; the browser job failed, but the full browser workflow then
  passed against a new isolated local database. The failed CI job was rerun; final
  remote status remains to be checked.
- Previous Warrior CI `39475473694` ultimately reports cancelled, not successful.
  Local full posture PostgreSQL verification (725 passed) remains the completed
  evidence; do not upgrade the cancelled remote run to a full CI pass.
- Another authorized deployment attempt still returned Railway's temporary-pause
  refusal. Active deployment remains `bc8360f4-80e9-4151-9ef4-7997e6023451` on old
  source `fc51e49`. The posture flag is staged; new source is not production verified.
- The next OPS-008 slice adds an operator-local read-only GitHub collector. It
  validates a repository commit and collects the current complete open-alert
  inventory, projects safe normalized fields and never sends its GitHub credential
  to Warrior. Fixed HTTPS API origin, redirect refusal, shared timeout, streamed
  limits and fail-closed provider/pagination/schema behavior are covered. Reports
  retain `admin_report` provenance; commit lookup is not proof of scanner execution
  on that revision. No scheduled server polling or independent attestation is added.
- Focused collector/normalizer verification passed 21 tests; all seven deliberate
  security mutations were killed. A real local rejecting-proxy smoke test confirmed
  the executable honored proxy settings without making a remote API request or
  emitting partial JSON. TypeScript and the final full source check passed (**914 tests, 3 skipped**).
  Publication is the remaining gate for this slice. No server route, database schema, transaction,
  licensing policy or commercial entitlement changed.

### Organization security overview — implementation and local verification

- Collector source `74dc28c` was committed and pushed atomically to the working
  and default branches after the 914-test source pass. CodeQL `39486054879` passed;
  CI `39486054908` is still running. PDF email CI `39483874808` passed on rerun,
  including its full browser workflow and real converter job. The first browser
  failure was not reproduced locally; no claim of its exact cause is made.
- Applications now has a read-only Security overview with direct scoped triage
  navigation. It prioritizes shown open critical/high snapshots, failed evidence,
  missing/stale reports and unavailable data. No report is called independently
  verified; zero shown snapshots and backup success never imply security/restore.
- Reads are capped defensively at ten applications and five environments each,
  in batches of four. Lists and unavailable reads disclose partial coverage.
  Session/authorization failures abort; navigation stops new batches and suppresses
  late responses. No server endpoint, authorization grant, database operation or
  commercial policy is added or changed.
- Six evidence-summary checks and five new real Chromium/API workflows passed.
  Ten deliberate mutations were killed, including scope/navigation gating,
  authorization refusal, truncation, stale evidence, restore separation and budgets.
  A mobile assertion initially used an exact cell accessible name, which includes
  a responsive column label; checking the actual advisory text corrected the test.
  Mobile layout had no horizontal overflow. Final full source/browser regressions
  and publication are the remaining gate. Full dependency audit: zero vulnerabilities.

### Final continuation checkpoint — 20 October 2026

- The read-only collector's exact source `74dc28c` passed full GitHub CI
  `39486054908`: PostgreSQL, browser, Windows, source quality and dependency/secret
  scanning all passed. CodeQL `39486054879` passed. This is completed remote
  evidence, unlike the older cancelled posture-source run.
- Final compact overview source passed `npm run check`: **920 passed, 3 skipped**.
  The final complete Chromium run passed **21 workflows** in **72.55 seconds**.
  Six pure evidence checks and ten killed mutations cover the new semantics and
  boundaries; full dependency audit found zero vulnerabilities. No API/schema,
  transaction, permission or licensing policy changed in the overview slice.
- Actual desktop/mobile screenshots were reviewed. Coverage details are collapsed
  while partial-coverage warnings remain visible. Row actions are short and have
  unique accessible environment labels. The 390-pixel view has no horizontal
  overflow. Local fixture previews are under
  `/workspace/scratch/warrior-security-overview/` (not production evidence).
- One complete rerun timed out after an existing SPA click had completed, while
  Playwright awaited document navigation. That helper now skips the generic
  navigation wait and keeps its explicit destination-heading wait. The isolated
  late-secret regression and the final complete 21-workflow run passed; no
  security assertion or timeout budget was removed or loosened.
- Railway again refused the authorized verified-source deployment with the same
  temporary-pause response. Do not claim that source publication updates the live
  UI or that the staged posture flag has deployed. The latest source still needs
  normal deployment/predeploy and synthetic live acceptance when Railway permits.
- Email source `234c3fb` is complete and CI-green, including browser/converter
  acceptance. Its hook still needs a matching Supabase-generated signing secret
  in the PDF Railway service plus hook enablement. No provider setting, real
  recipient, production file/export, payment, licensing key or MFA policy changed.

Next actions, with existing implementation authority retained:

1. Deploy the current default branch when Railway allows it. Verify the served
   `operations.mjs` bytes, `/healthz`, `/readyz`, migration 0024 and grants; then run
   the synthetic posture acceptance helper. Fixture restore reports are not actual
   production restore exercises. Retain the old service and all evidence on rollback.
2. Configure the PDF email hook through secure Railway/Supabase administration;
   finish controlled-address delivery and confirmation/recovery acceptance only
   when that external access and an authorized test recipient are available.
3. Bind the real PDF monitoring source with a genuine owner/admin fresh-MFA scoped
   credential and PDF-project deployment access. Never substitute a synthetic
   fixture credential or database/provider bypass for this authorization boundary.
4. Keep independent monitoring/witness deployment, production backup/restore drills,
   external notification providers and physical Windows release acceptance as
   separate unverified rollout gates. Initial operations work does not establish
   those results or complete deferred billing/federation/hardware milestones.

- Organization overview implementation committed as `11cd23a`. Final read-only
  public checks returned HTTP 200 from `/healthz` and `/readyz`; the served
  `operations.mjs` digest still differs from the new source, confirming that the
  published UI must not be represented as deployed. The current checkpoint changes
  documentation only; the verified application and tests are unchanged.

### Railway resumed — production acceptance, 20 October 2026

- Exact source `67730ada0a07b15ce5db72da6f4ee7600b2ccb23` passed GitHub CI
  `39489285630` and CodeQL `39489285760`. Railway deployment
  `6eb3fceb-22b1-4d55-b2b5-15799650dd9d` reached **SUCCESS** on that exact commit.
  An initial deployment without an explicit SHA restarted the older `fc51e49`
  release; the subsequent explicit-SHA deployment is the accepted release.
- Production inventory and posture flags are enabled. Deployment logs confirm
  migration 0024, grants and completed predeploy profile verification. All twelve
  database checks passed, including TLS, migration completeness, least privilege,
  append-only audit, required grants and table coverage.
- Public `/healthz` and `/readyz` returned HTTP 200. Served `operations.mjs`
  matches the tested source byte for byte (SHA-256
  `39bed294c3945f9070c37912ee1237c42824119e6729b53d20658ab50d454723`).
  Owners/admins can open **Applications → Review security overview**, then
  **Review** an environment's findings or **Open environment** for its controls.
- Live isolated synthetic acceptance passed normalized scan import and exact
  deduplication, refusal of raw extra fields, assigned finding remediation,
  stale-version conflict, separate backup/restore reports and rejection of a
  successful restore report lacking passed checks. Calculated reported RPO/RTO
  and the explicit `independently_verified: false` boundary passed. Synthetic
  application/environment/component inventory was archived and the session logged
  out; audit/evidence history remains intact.
- This was live API acceptance plus exact served-source verification; the 21
  Chromium workflows remain local browser evidence. Synthetic recovery reports
  are **not an actual production restore**, and the GitHub collector has not had
  authenticated live provider acceptance.
- The earlier Railway rollout blocker is resolved. PDF email hook activation,
  genuine fresh-MFA PDF monitoring binding, independent witness/monitoring,
  production restore drills, external delivery and physical Windows acceptance
  remain separate gates. Cloudflare standby is an assessment only; no redundant
  deployment or traffic failover is active.

Next: securely activate the PDF authentication-email hook when its Railway and
Supabase administration are available; complete controlled-recipient confirmation
and recovery acceptance. Bind PDF monitoring only with its genuine scoped MFA
credential. Do not bypass these external-access or authorization requirements.

### Actionable alert response guides — 20 October 2026

- Reconciled default source `3887500`. Existing rules stored a reviewed response
  guide enum but the dashboard offered no way to open its instructions. The next
  independent OPS-006/008 completion slice exposes that existing choice through
  **Automatic alerts → Open response guide**, without waiting for PDF credentials.
- Guides cover general component investigation, scanner, converter, storage and
  email delivery, identify the affected component, require fresh/synthetic recovery
  checks and explain owner/provider escalation. They preserve scanner refusal,
  customer objects and email confirmation. Provider acceptance is not inbox delivery;
  incident resolution is not service repair and backup success is not restoration.
- The existing modal and scoped rule reads are reused. Opening a guide causes no
  API mutation, command execution, external navigation, provider call or message.
  Unknown/inherited codes cannot select a guide. Server permissions, routes,
  database schema, audit transitions and licensing policy are unchanged.
- Twelve focused unit checks passed; four deliberate mutations were killed for
  inherited selection and scanner/email/storage safety instructions. Full
  `npm run check` passed: **932 passed, 3 skipped**. All **21 real Chromium
  workflows** passed, including guide/component/recovery/escalation rendering,
  zero guide-opening mutations and continued rule evaluation/maintenance/toggling.
  An initial browser assertion used a Playwright matcher with Vitest; it was
  corrected to assert the actual dialog text, then the complete suite passed.
- No persistence or server boundary changed, so no additional PostgreSQL/load
  scenario was introduced. Deployment acceptance remains separate from local
  browser evidence. Next: publish the verified source, deploy its exact SHA and
  check public health/readiness and exact served `operations.mjs` bytes.

Response-guide publication and rollout:

- Source committed/pushed as `089643dbd28a020fe466552d13aada056f7f4e77`.
  Railway automatic deployment `352cf8dc-2aea-48a7-8d55-28686b9e5b2f` reached
  **SUCCESS** on that exact source. A concurrent explicit request
  `d2ef4c4a-1505-4904-9bde-8765f4e068ea` failed; it is not deployment evidence.
  Future pushes should first check automatic deployment before issuing a duplicate.
- Successful release logs confirm completed predeploy migrations/grants/profile
  verification and all twelve database checks passed. Public health and readiness
  returned HTTP 200. Served `operations.mjs` matches the source exactly, SHA-256
  `6ccc3be4c15148f4e7727c2c515f1bbaafdee389fe7dd79dae92468b1d88a50c`.
- Browser acceptance remains the local complete 21-workflow suite, not an
  authenticated production browser exercise. Exact-source remote CI `39518443617`
  and CodeQL `39518443525` were running at publication; do not call them green
  without checking their completed outcome.
- Next independent rollout gates remain real PDF source binding with genuine
  scoped fresh-MFA credentials, independent monitoring/witness deployment,
  controlled production recovery drills and physical Windows release acceptance.
  PDF authentication-email activation has moved to the PDF chat. No external
  alert recipient, infrastructure remediation or Cloudflare failover was enabled.

### Continuous verification checkpoint — 21 October 2026

- Reconciled the current default branch at `93c15c2`; OPS-004–008 implementation
  and the explicit predeploy runner already exist. Do not repeat the older
  OPS-004 implementation instructions in historical checkpoints.
- Exact-head CI `39518709818` and CodeQL `39518709710` completed successfully.
  All applicable source, PostgreSQL, browser, Windows and dependency/secret jobs
  passed; PR-only dependency review was correctly skipped. Earlier source run
  `39518443617` was cancelled, superseded by this completed verification.
- Current Railway inspection reports API deployment
  `5ca309cd-e18d-4a50-a408-594249888ec9` SUCCESS with one running replica;
  the sharing scanner is also online. No pending work, warnings, critical issues
  or recent deployment failures were reported. This status inspection does not
  establish a new authenticated PDF-source integration or restore exercise.
- CI now offers manual dispatch and a weekly Monday 03:43 UTC run. The existing
  full checks, including high-severity dependency audit and secret scanning, run
  even without a source change; CodeQL retains its separate weekly schedule.
  Scheduled runs use GitHub's default branch and may be delayed by GitHub. They
  do not deploy source, ingest findings into Warrior, or send Warrior alerts.
- Verification: workflow YAML parsed and its schedule/manual entry points and
  unchanged security gate were checked. Full `npm run check` passed after locked
  dependencies were installed and local test networking enabled. The initial
  sandbox-restricted run was stopped after network-dependent tests failed; no
  assertions were weakened. No application, database or authorization code changed.
- Next-agent action: verify the new exact-head CI after publication. For live PDF
  source binding, obtain PDF-project access through the secure environment field
  and a genuine owner/admin fresh-MFA environment credential. Do not use synthetic
  acceptance identities or bypass MFA. Independent monitoring/witness rollout,
  controlled production restore drills and physical Windows acceptance remain
  unverified gates. Authentication-email activation stays in the PDF chat.

### Incident review filters — 21 October 2026

- Added state and severity filters to the existing scoped incident dashboard.
  Matching/loaded counts and explicit remaining-page disclosure prevent a filtered
  empty view from being presented as a complete incident inventory. Pagination
  remains available when no loaded rows match; clearing filters restores loaded
  rows. Filters reset with the current view rather than persisting tenant state.
- No server route, authorization, schema, audit transition, commercial entitlement
  or external provider changed. Browser acceptance covers combined filters,
  no-match counts, clearing and continued real-API triage; a controlled paginated
  read fixture covers finding a match on the next page without dropping filters.
- Initial full source verification passed **932 tests, 3 skipped** and all **22
  browser workflows** passed. A deliberate removal of the severity predicate was
  caught by the browser regression. The first mutation run instead exposed an
  ambiguous existing field selector; it was corrected to use the exact accessible
  name and passed before the actual mutation check. Filters have explicit accessible
  names. Final full source verification again passed **932 tests, 3 skipped**;
  the final complete browser suite passed **22 workflows**. No persistence or server
  boundary changed, so additional PostgreSQL/load scenarios were not required.
  Next: publish, check exact-head CI and verify the automatic Railway deployment;
  local browser evidence alone is not authenticated production acceptance.
- Previous release `746c905` now has completed successful exact-head source, browser,
  PostgreSQL, Windows, dependency/secret and CodeQL checks; PR-only dependency
  review was correctly skipped. Live PDF binding, independent monitoring/witnessing
  and production restore retain the previously documented acceptance gates.

### Independent availability observer — 21 October 2026

- Incident-filter source `977fe9e` completed all applicable exact-head CI and
  CodeQL checks successfully. Railway still serves `93c15c2`; an authorized
  source reconnect was refused with `Deploys have been paused temporarily`.
  Do not present the published incident filters as production deployed.
- Added a separate GitHub Actions observer for Warrior's fixed public liveness
  and database-readiness endpoints, scheduled approximately every ten minutes
  and manually runnable. No credentials, user destinations, redirects, provider
  messages or production mutations are involved. Either failed endpoint fails
  the job; results never imply connected-application health or restore evidence.
- Response schema/size/cache validation, whole-request deadlines and safe output
  keep this independent observer bounded. GitHub schedule delay or missing runs
  remain explicit gaps, not healthy observations. The workflow does not ingest
  observations or open incidents inside Warrior.
- Local verification: full `npm run check` passed **942 tests, 3 skipped**. Ten
  focused transport tests pass. Four deliberate mutations (HTTP status, body limit,
  exact schema and timeout refusal) were killed by assertions; the original source
  was restored and the focused suite passed again. Workflow YAML, read-only job
  permissions and bounded runtime were checked. No application/API/database or
  licensing behavior changed.
- Next: publish and observe the first remote availability run. Local injected
  transport tests alone are not live external acceptance.
  Retry the tested UI deployment when Railway permits, then verify served bytes.
  Real PDF binding, independent audit witness, production restore drills and
  controlled notification delivery retain their separate acceptance requirements.

Observer publication and live acceptance:

- Source `ed51a95da1726f7da00fdc0f48c4020043a3bcaf` was published to the default
  branch. Independent workflow run `39576119326`, job `119141954961`, completed
  successfully on that exact SHA. Its logs report both `liveness: passed` and
  `readiness: passed` from the GitHub-hosted runner at 09:20 UTC on 21 October 2026.
- This establishes one actual external observation and a configured schedule, not
  continuous uptime, notification delivery, PDF source binding or recovery proof.
  Full source CI/CodeQL for the new source remain separate from this observer job.
- The observer runs without a Railway release. The incident-filter UI deployment
  remains blocked by Railway's temporary deployment pause. Next agent: verify the
  newest exact-head CI, retry rollout when permitted and verify served source bytes;
  retain the healthy existing release and do not bypass provider or MFA boundaries.

### Cloudflare alternative preparation — 21 October 2026

- User requested a prepared alternative deployment. Added an isolated, pinned
  Wrangler/Containers package using the existing Node Dockerfile, singleton
  routing, disabled traffic/public previews, strict runtime-secret allowlist and
  origin validation, fixed safe refusals and overwritten edge forwarding headers.
  Migration-owner credentials and production guard/scanner bypasses are rejected.
- Worker bundling passes with `--dry-run --containers-rollout none`; 23 focused
  runtime/gateway tests pass. This is not a Docker-image build, provider deployment
  or successful production container start. No account resource, DNS, secret,
  customer data or traffic has been changed.
- The deployment guide documents separate predeploy migrations/grants/profile
  verification, existing-key preservation, external PostgreSQL/TLS, unreachable
  Railway-private scanner addressing, staging/cutover/rollback and overlapping
  background-worker risks. Plain Workers/Pages are not compatible replacements.
- Final source check passed **966 tests, 3 skipped**. All **24 focused gateway
  tests** pass, including the per-binding UTF-8 byte cap. Deliberate removals of
  traffic gating, origin checks, the secret allowlist and trusted forwarding were
  killed by assertions; restored-source focused tests pass. The final Wrangler
  dry-run bundle passes, and the isolated package audit found zero vulnerabilities.
  Added a separate CI bundle/audit job. Secrets are individual reviewed bindings
  because Cloudflare limits variable values to 5 KB; no aggregate secret is used.
- Next: verify the new exact-head CI, then perform an actual image build and
  isolated Cloudflare staging acceptance with account access, reviewed secrets and
  the chosen hostname. No Docker-image or live Cloudflare acceptance is claimed.
  Do not mark standby/failover active from a successful bundle alone.

### Approved cloud-console restyle

- User explicitly approved the desktop/mobile concept and requested implementation.
  Reworked the shared portal shell/styles with compact neutral surfaces, orange
  actions/selection, icon navigation, full-width utility header, status badges,
  responsive table records and two-column wide-screen forms. Existing Warrior
  branding and Quantix ownership remain; no Cloudflare affiliation is claimed.
- Added an accessible mobile menu with announced expanded state, Escape/focus
  restoration, close-on-navigation, desktop/mobile reset and sign-out cleanup.
  No route, authorization, session persistence, CSP, database or licensing behavior
  changed. Credential clearing and stale-response guards remain intact.
- Initial existing browser suite passed all 22 workflows. The new real browser/API
  shell check passes desktop, 390-pixel portrait, 740-pixel landscape, keyboard,
  navigation focus and sign-out behavior. Actual synthetic screenshots were
  reviewed; final full verification/publication evidence follows after checks.
- Focused keyboard/mobile checks pass; deliberate Escape-close and sign-out-reset
  removals were caught at their respective assertions. A stale test field selector
  and hidden-element lookup were corrected without removing behavior assertions;
  resize focus awaits browser media-query delivery. Primary text contrast is
  5.43:1, muted text 5.24:1 and active-navigation text 6.00:1.
- Final `npm run check` passed **966 tests, 3 skipped**. The complete Chromium
  suite passed **23 workflows**, including the responsive-shell regression and
  existing credential/triage/security flows. Actual synthetic desktop/mobile
  screenshots were reviewed. No database/server boundary changed, so additional
  PostgreSQL/load scenarios were not required for this UI-only change.
- Next: verify the published exact-head CI, then confirm deployment/served assets
  after the provider outage. Local screenshots alone are not production evidence.
  Cloudflare remains prepared rather than activated, and the earlier Railway pause
  and live PDF source-binding requirements remain separate rollout gates.

- The user reports a Railway outage. A deployment-status lookup did not return
  usable service state; no deployment or traffic change is claimed. Continue local
  UI verification and publication independently; resume live rollout only when
  the provider is available. Do not activate the prepared Cloudflare alternative
  or substitute credentials as an implicit response to the outage.
- The complete browser rerun exposed a real breakpoint focus edge case: the browser
  can blur a hidden desktop navigation link to body before matchMedia fires. The
  handler now restores Menu focus in that case while preserving focus in visible
  form controls. The regression retains its focus assertion and awaits delivery.

### Cloudflare alternative execution — 22 October 2026

- User confirmed a paid Cloudflare account with Containers enabled and chose
  `warrior.quantixsl.com`. Added that custom-domain binding while retaining
  disabled application traffic and disabled public preview endpoints. No DNS or
  provider resource is changed by the source commit itself.
- Built the actual image with Node 22.23.4. The first startup exposed restrictive
  local checkout permissions in copied source. The Dockerfile now normalizes
  read/traverse permissions while leaving code root-owned and non-writable to
  runtime UID 1000. Optional BuildKit CA mounting retains strict npm TLS checks
  without baking the managed-session certificate into the image.
- The rebuilt non-root image passed liveness, synthetic fixture readiness and
  byte-exact HTML/CSS/portal/operations assets. Production startup without required
  credentials is refused; this is not live production database acceptance.
- Added a manual, default-branch GitHub deployment workflow using the protected
  `cloudflare-standby` environment. Credentials are scoped to the deployment step;
  the workflow requires successful exact-revision CI and a fixed-host, disabled
  traffic/single-container configuration before provisioning. Source push alone
  does not deploy. CI also performs an actual local image build/start/assets check.
- Cloudflare provider credentials are not configured in this session. The user
  was asked to add account ID/API token in the GitHub environment's secure secret
  fields. Runtime database/signing/MFA/etc. bindings remain a separate setup step.
  Do not collect those values in chat, rotate existing keys, enable overlapping
  production workers or claim automatic failover.
- Verification: full `npm run check` passed (979 passed, 3 skipped); the release
  policy passed 13 tests and killed four deliberate guard mutations. The selected
  hostname Worker bundle and actual non-root container smoke check passed.
  Git checkout authentication failed; publication uses the connected GitHub API
  with an expected-head lease instead. Remote CI and provider provisioning remain
  separate evidence; neither is implied by these local checks.

### Railway recovery via GitHub — 22 October 2026

- User reports Railway deployment access restored and requests the existing
  GitHub-to-Railway auto-deploy path. Do not substitute a direct CLI upload or
  provision another service. Cloudflare remains a prepared, disabled alternative.
- Published source `0b84104dbb3506ef6c61bddab3fb2d460daf678e` passed all required
  GitHub checks: source, PostgreSQL, browser, Windows, dependency/secret scan,
  Cloudflare image/bundle and CodeQL. External liveness/readiness checks passed
  too, but do not establish which revision the running host serves.
- GitHub commit statuses expose no Railway deployment result for that revision.
  This handoff update supplies a new push on the connected default branch after
  the outage. Verify the resulting CI and live UI assets before claiming rollout.
  If Railway does not consume the push, inspect its GitHub source/auto-deploy
  configuration with the owner rather than changing production credentials.

### Railway builder compatibility fix — 22 October 2026

- Uploaded build log proves Railway builder v4 rejects the optional BuildKit
  secret mount at Dockerfile line 11. Removed that mount from the shared
  Dockerfile; npm retains strict TLS verification and the non-root runtime
  retains read-only access to source. No application credentials are changed.
- Supersedes the earlier optional proxy-CA mount guidance. Managed local builds
  may need their own approved CA-capable build environment; do not reintroduce
  an unsupported mount or disable TLS verification in the Railway Dockerfile.
- Push this compatibility fix through the existing GitHub auto-deploy path.
  Confirm Railway build/start and live assets before claiming recovery.
- Validation: `npm run check` passed (979 tests passed, 3 skipped). Remote
  image-build and Railway rollout evidence must still be checked after publication.

### Release observation completion slice — 22 October 2026

- Builder-fix source `afa38c5` passed Linux source, PostgreSQL, browser,
  dependency/secret, CodeQL and actual image/bundle checks. Windows DPAPI hit its
  existing 15-second deadline; the follow-up disposable diagnostic passed all
  seven steps. Requested one exact-source Windows job retry; no runtime timeout
  or encryption assertion was weakened.
- Added independent GitHub release observation: fixed public liveness/readiness
  plus exact-source hashes for HTML/CSS/portal/operations JavaScript, a six-minute
  rollout window and fixed non-sensitive output. Existing scheduled availability
  checks remain independent. No provider credentials, account connection,
  production mutation, private data or external notification is involved.
- Nine focused checks pass for matching source, failed readiness, older assets,
  failed/cached/oversized responses and stalled transport/body cancellation.
  Mutation checks remove hash, readiness and cache guards independently. Full
  source verification and exact-head live observation follow publication.
- Remaining implementation is not equivalent to external activation: actual PDF
  source binding still needs genuine scoped fresh-MFA credentials; independent
  audit witness, controlled restore drills, native installer acceptance and
  configured notification providers need their documented real environments.
  Automatic infrastructure remediation remains deferred by the accepted program.
- Final local verification: all 988 tests passed (3 skipped), all nine observer
  tests passed, and three deliberately removed guards were caught. Exact-source
  Windows retry for `afa38c5` passed. Live observer outcome is recorded separately.

### Recurring recovery acceptance slice — 22 October 2026

- Live release observation for source `0a222fd` passed at 22:25 UTC: public
  liveness/readiness and exact HTML/CSS/portal/operations assets. This establishes
  deployed UI bytes, not authenticated application or real PDF-source acceptance.
- Added a credential-free scheduled/manual GitHub workflow for the existing
  isolated logical-backup/restore drill. It uses a disposable loopback PostgreSQL
  container, fsync, newly generated fixture databases, real pg_dump/pg_restore,
  application reads and audit integrity assertions, followed by container cleanup.
  Relevant source pushes also run the exercise. No production data is accessed.
- The recorded measurement remains explicitly synthetic: no claim of production
  RPO/RTO, provider backup verification, PITR, independent witnessing or key recovery.
  Remote exercise/source checks follow publication. Live PDF integration and
  real provider configuration remain blocked by their secure setup prerequisites.
- Full local source checks passed: 988 tests, 3 skipped. CI must exercise the
  actual disposable PostgreSQL restore before this workflow is marked accepted.

### Guided onboarding and requested factory reset — 23 October 2026

- User authorized the review recommendations and explicitly selected a factory
  reset including Warrior application data. No deletion has been executed.
  Reset is not an auto-deploy migration. Correct project/schema, exclusive object
  ownership and maintenance access must be verified first. The connected Supabase
  account exposes six projects, none with trust.operations_applications visible.
  Asked for the Warrior project name/dashboard URL only; never collect secrets in chat.
- Added fresh account-MFA prerequisite gating and an Account navigation action
  for credential management, with metadata still visible and backend checks intact.
  Manual-key enrollment explains its three steps, second password entry, expiry,
  pending-key replacement and post-confirmation sign-out/recovery behavior.
  Added parent context to application/environment/component creation screens.
- Added fixed export-visible credential rejection category/status/reference
  diagnostics, excluding raw bodies, factors, tokens, unknown fields and paths.
  A regression first failed without the diagnostic, then passed with it.
- Published-current source remains 60189ce until this change is checked/published.
  Guided browser suite passed 24 workflows; diagnostic suite passed six tests.
  Mutation checks, full checks and final publication evidence follow.
- Current operator guide separates implemented features from provider activation
  and real acceptance. Historical guides are labeled; prior history is retained.
  Factory reset will also remove owner/operator accounts, licenses and audit records;
  re-registration and audited operator bootstrap are necessary afterward. Separate
  Rokela PDF databases/files and existing external security keys are outside scope.
- Final verification: full source check passed 989 tests (3 skipped), complete
  guided browser suite passed 24 workflows and both intentional MFA-readiness and
  secret-logging mutations were caught. Current GitHub/source search contains no
  actual project-specific Supabase hostname; DATABASE_URL is deployment config.
  Factory reset remains blocked on verified live target and maintenance access.

### Rokela PDF external availability observer — 24 October 2026

- Requested by the owner after two Rokela PDF outages on 24 October (a startup crash on
  a malformed monitoring setting, then a production sign-in redirect loop) that no alert
  caught. Added `tools/check-rokela-availability.mjs` and the separate
  **Rokela PDF external availability** workflow (every ten minutes, GitHub-hosted, so it
  also reports when Railway itself is down). It checks `/api/v1/health` for exactly
  `{"ok":true}` and that `/signin` is served directly (no redirect) as the Rokela PDF page.
  Warrior's own observer and release check are unchanged.
- Local verification: `services/platform-api/test/rokela-availability.test.mjs` (17 tests)
  covers healthy responses, 500/503, wrong or extra JSON, wrong content type, cached and
  oversized bodies, transport errors, redirect responses and refusal, error and wrong pages,
  stalled transport and endless bodies. Six deliberate mutations (follow redirects, ignore
  status, ignore the ok value, ignore the page title, drop the size limit, accept cached
  responses) were each caught; the source was restored. A live local run against production
  passed both checks, and a real redirect (`rokelapdf.com/signin` → `www`) was refused.
- Not established: a live scheduled run on GitHub, or that the failure email reaches the
  owner. That depends on the owner account's Actions notification settings.
- Next: after merge, confirm the first scheduled run passes, and confirm failed-run email is
  enabled for the owner account. The Warrior-side features (missing-heartbeat incidents for
  Rokela PDF, outside-in probes run by Warrior, incident email delivery) remain separate work.

### Dependency security updates — 24 October 2026

- New advisories turned the `npm audit --audit-level=high` CI gates red on the base branch
  (seen on PR #31): zod `GHSA-mrhx-c7xc-m3w5` (high, fixed only in zod 4), undici in the
  Cloudflare package (high: `GHSA-4qv8-2p9j-2685`, `GHSA-f72v-6w45-q472`,
  `GHSA-xjj6-f33q-929c`), plus moderate fast-uri and low fastify advisories.
- Root: zod 3.25.76 → 4.6.7 in `services/platform-api`, fastify 5.12.5 → 5.12.7, and fast-uri
  4.2.1 → 4.2.3 (plus ajv's nested copy 3.1.8 → 3.1.9). Only one code change was needed:
  `z.record` now takes an explicit key schema, so the four record schemas in `schemas.ts`
  are now `z.record(z.string(), …)`.
- Visible API effect: the `details.issues` entries on a 400 validation error (`path: code`)
  now use zod 4's issue codes. For example, a bad e-mail or UUID now reports
  `invalid_format`, not `invalid_string`. No source or test depended on the old names. The
  error type, status and the strict rejection of unknown fields are unchanged. Zod 4 is also
  stricter about numbers (it rejects non-finite and unsafe integers).
- Cloudflare: wrangler stays at 4.151.3. The latest release (4.152.0) still pins undici
  7.29.1, so `infrastructure/cloudflare/package.json` overrides undici to 7.30.1. Remove the
  override once a wrangler release ships a patched undici.
- Verification: both audit gates report 0 vulnerabilities. `npm run check` passed (1006
  tests, 3 skipped), the Cloudflare bundle builds, and `npm run test:db` was run on
  PostgreSQL as superuser and as the app role: 727 tests passed.

### Incident email and silent-source alerting — 24 October 2026

- Owner request: build alerting into Warrior instead of a third-party monitor (step 2:
  missing-heartbeat incidents, incident email, then Warrior-run probes). This change
  delivers the first two; probes remain a separate change needing the SSRF policy above.
- Missing heartbeats: reconciling current code showed the evaluator already treats a
  component whose last report is 180 s stale as breaching (stored reports live 30 days,
  so silence does not decay to `unknown`). Added a regression test (healthy → silent
  → one incident → fresh reports resolve it). No evaluator change was needed. Rokela PDF
  already sends API, scanner and converter heartbeats every minute.
- Email: new opt-in `OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED` wires the existing fenced
  outbox port to the transactional mail provider (ADR-029 amendment, threat model and
  contract updated). Recipient is the rule creator's verified account address looked
  up at send time; fixed plain-text template; retries/72 h deadline unchanged. Added
  Cloudflare Email Sending as a provider, chosen only by an explicit `MAIL_PROVIDER=cloudflare`
  (existing Resend settings behave exactly as before); identity mail can use either. The
  Cloudflare standby allowlist forwards the four new settings. No route, schema, migration or grant changed.
- Local verification: new `operations-email.test.ts` (6 tests: config gating, provider
  selection, end-to-end silent component → email → recovery email over real HTTP
  ingestion, flag-off portal only, unverified recipient refused, provider outage
  backoff → failed), 5 Cloudflare transport tests, and the evaluator regression test.
  Eight mutations were each caught: verified-recipient check, redirect refusal,
  recipient acceptance, permanent bounce, account-ID format, flag-requires-provider,
  flag-gates-delivery and stale-heartbeat breach.
- PostgreSQL: the email suite now also runs in the `db` and `db-approle` projects; full
  `npm run test:db` passed (727 tests) and the email/automation suites pass on both roles.
- Not established: no real email was sent; production has no rule or email settings
  from this change. Rollout steps are in the automation guide (Incident email).
- Next: owner configures Cloudflare Email Sending for Warrior, verifies their Warrior
  account email, creates heartbeat rules for Rokela PDF's components and runs the
  synthetic acceptance in the guide. Then design Warrior-run probes (fixed operator-set
  HTTPS targets, DNS/redirect/private-address refusal) as their own ADR amendment.

### Warrior probes — 24 October 2026

- Step 2, part 2 of the owner's request: Warrior checks public pages itself and alerts
  through rules, catching failures an application cannot report (the 24 October sign-in
  redirect loop happened while Rokela PDF still sent healthy heartbeats).
- Implemented (ADR-029 probe amendment, threat model "Warrior probes", contract, guide):
  opt-in `OPERATIONS_PROBES_ENABLED` + operator-only `OPERATIONS_PROBE_TARGETS` (≤10;
  HTTPS:443 public DNS names; every resolved address must be public, checked inside the
  connection's lookup; no redirects/proxy/credentials; 10 s; 256 KiB; pass/fail only).
  Results are stored separately in `operations_probe_results` (migration 0025, app-role
  grants) and evaluated only by the new `probe` rule kind. 60-second runner in `main.ts`.
  Route schema, OpenAPI enum, dashboard rule form and Cloudflare standby allowlist updated.
- Local verification: `operations-probes.test.ts` (46 tests, including a real local HTTPS
  server with a throwaway CA: blocklist table, rebinding-safe lookup, redirect, error,
  cached, oversized, invalid UTF-8/JSON, stalled body, untrusted certificate, IP literals
  with zero connections, config refusals that never echo values, wrong-scope recording,
  and end to end failing probe → incident → email → recovery email); probe-rule evaluator
  test; probe-result store contract on memory and PostgreSQL. Thirteen mutations were each
  caught. Load scenarios `automatic-alerts-contention` (1 incident, 1 delivery attempt,
  2 intents from 20 contenders, audit verified) and `operations-events-contention-retention`
  (retention batches 1000/101/0, zero remaining bytes, stale after 180 s, audit verified)
  match their asserted expectations with fsync on.
- PostgreSQL caught a migration defect before publication: 0023's kind/event check has a
  generated name (`…_check1`), and dropping `operations_alert_rules_check` by name would
  have removed the `updated_at >= created_at` check instead. 0025 now finds the kind/event
  check by definition (exactly one match required); a schema test proves the timestamp
  check survives and the replacement allows `probe` (mutation to the by-name drop caught).
- Not established: no probe has run against a real site from Warrior; production has no
  probe settings. Probes share Railway's network fate; the GitHub observers stay the
  independent check.
- Next (owner): create `public-site` and `signin` components under Rokela PDF production,
  set the two example targets from the automation guide, create `probe` rules, and confirm
  the rules show `healthy` within two minutes.

### Probe visibility follow-up — 24 October 2026

- During production enablement the owner looked for probe results in **Reported health**,
  which showed only backend reports (`unknown` for the probe components). Added a separate
  per-component `probe` object to the health read (OpenAPI updated) and **Warrior check** /
  **Last checked** columns in the dashboard; it never alters backend status, dependency
  propagation or `independent_probe`. Startup now logs `operations probes enabled for N
target(s)` (count only).
- Production state reported by the owner (not independently verified here): migration 0025
  applied with all profile checks passing; API, scanner and converter heartbeats arriving
  `healthy`; heartbeat and probe rules created; probe rule observations still `unknown` at
  the time of this change, cause not yet established.
- Verification: health unit test (separation, staleness, inactive and post-change epochs),
  API wire assertion and browser column assertion; four mutations each caught.

### Recovery acceptance and activation follow-up — 24 October 2026

- Current baseline 40056f6 includes Claude's dependency security updates, incident
  email and configured-page probes; its CI passes. The separate synthetic recovery
  workflow failed because its ledger check and output were hardcoded to 24 while
  migration 0025 is now present.
- Replace that count with a read-only full ledger comparison against exact current
  SQL file identities/checksums. Missing, unknown, duplicate, altered or swapped
  migrations fail; new forward migrations are included automatically. The workflow
  now tracks changes to this verifier and its regression tests.
- Prepared production audit-witness deployment specification in
  docs/deploy/audit-witness-setup.md: separate AWS account, retention-locked S3
  COMPLIANCE evidence, append-only HTTPS receiver contract, restricted credentials,
  acceptance and activation steps. No witness or billable resources provisioned.
- Read-only production metadata showed no successful anchor, no notification
  records and owner email not verified. Preserve real email verification; do not
  bypass it or call provider acceptance inbox delivery. No production email sent.
- Verification: see subsequent evidence below before treating the repair as shipped.
- Repair evidence: `npm run check` passed 1075 tests (3 skipped). Seven new ledger
  tests passed; weakening comparison to counts only was caught by wrong-version
  and wrong-checksum cases, then source restored and tests rerun. The real isolated
  fsync-on pg_dump/pg_restore drill passed with 25 migrations, application fixture
  and audit verification, excluding the post-snapshot user (about 2 seconds on this
  local fixture, not a production recovery-time claim). Production database,
  anchors, email settings and notification recipients were not changed.
- Concrete next actions: deploy the repair through GitHub and verify the synthetic
  recovery job; owner verifies account email and configures/accepts provider email;
  select independent AWS account and confirm retention before implementing and
  provisioning the production witness receiver. Do not disable audit warnings or
  claim anchoring enabled from this specification alone.
