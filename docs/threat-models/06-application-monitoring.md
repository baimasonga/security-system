# Application monitoring threat model

Status: **accepted; inventory, credential, event, health and incident controls implemented. OPS-008 adds separately gated administrator evidence and finding triage; verification/rollout evidence belongs in the handoff**.
19 October 2026. Normative limits/protocol: [operations contract](../api/operations-contract.md).
Scope: inventory, integrations, ingestion, health history, alerts and incidents; read-only first milestone.

## Assets and boundaries

Protect integration credentials, operational evidence, application/tenant boundaries, notification
destinations, incident state, audit integrity and availability of Warrior and connected systems.
Browser clients, connected backends and independent observers are distinct sources. A compromised
connected backend and a stolen active integration credential are in scope. Collector, durable store,
workers, account UI, notification provider and monitored networks are separate boundaries. Monitoring
authority must never imply commercial entitlements, infrastructure credentials or remediation authority.

| Threat                                                 | Chosen control                                                                                                                                                         | Required implementation/operational test                                                                                                                                     |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant/application/environment spoofing                | Derive scope/source from scoped credential row; strict unknown-field rejection; component ancestor checks; separate `ops:*` permissions                                | A credential cannot supply another scope or reference another environment's component; every read/mutation denies another tenant (OPS-002–004).                              |
| Privilege escalation through Product/operator identity | Optional Product mapping has no auth meaning; operators get no new tenant bypass; no licensing imports in operations                                                   | Member/operator/credential cannot gain membership, license, rule or remediation authority (OPS-002/003).                                                                     |
| Secret theft or reuse after rotation                   | One-time no-store secret, SHA-256 digest, timing-safe dummy comparison, TTL, bounded overlap, transactional revocation                                                 | Secret absent from logs, metadata and repeated issuance reads; no DB plaintext; old credential stops at expiry/revoke and rotation cannot extend it (OPS-003).               |
| Ingestion/revocation race                              | Parent-to-child locks, credential status rechecked under ingestion transaction; no cached authority on commit                                                          | Revoke wins → refusal; ingest wins → one committed receipt; deadlock retry cannot bypass revocation (OPS-003/004).                                                           |
| Replay/changed retry or false acknowledgement          | Scoped UUID + canonical hash, 30-day identity retention, dedup before quota, atomic batch, commit before 200                                                           | Crash before/after commit, concurrent retry/rotation, reordered JSON, changed payload and duplicate-ID batch conflict; DB failure returns no success (OPS-004).              |
| False evidence from compromised backend                | Immutable `backend_report` provenance; server-owned severity, no claimed independent-probe/audit authority                                                             | Browser report cannot impersonate backend; backend malware assertion is never labeled platform-confirmed; future source types require review (OPS-004/005).                  |
| PII, file content, private links, covert channels      | Exact enumerations/numeric bounds, structural ID/time validators, ADR-027 checks, no arbitrary names/job correlations; fixed safe diagnostics                          | Unknown fields rejected; filenames/recipients/tokens/paths never reach DB/logs/errors; unknown field names are not reflected (OPS-004).                                      |
| Quota/storage or alert flood                           | Credential request/IP limits, atomic env/org event/storage caps, bounded batches/outbox, receipt-time rule windows, unique active incidents                            | Concurrent submissions cannot exceed quota; duplicates charge once; one noisy environment cannot consume another's budget; storm produces one active incident (OPS-004/006). |
| Monitoring outage damages business work                | Durable bounded source outbox outside business transaction; jitter/retry classification; 503 commit failure                                                            | Collector outage fills bounded queue, exposes drops/backlog, and does not fail conversion/upload/download/license behavior (OPS-004/007).                                    |
| SSRF, metadata access and lateral scanning             | Probes take operator-configured targets only, under the public-address/DNS/redirect policy in "Warrior probes" below; event/inventory destination fields stay rejected | Submitted URLs never execute; probe tests cover private/loopback/link-local/mapped IPv6, DNS rebinding, redirects and resource exhaustion (OPS-005 probe amendment).         |
| Stale/absent data presented as healthy                 | Receipt-time freshness, explicit unknown/stale, persisted history, independent Warrior monitoring                                                                      | Missing/stale heartbeat and restart gaps cannot be healthy; maintenance suppresses notifications without changing health truth (OPS-005).                                    |
| Unauthorized rules/incidents/destinations              | Separate permissions, same-org assignee, verified destinations, mandatory reason and atomic audit                                                                      | Ordinary member cannot modify, cross-org assignee denied, audit failure rolls back, event cannot choose a destination (OPS-006).                                             |
| Duplicate notification or provider outage              | Transactional outbox, fenced worker claims, 72-hour bounded retry, stable incident ID, visible failed state                                                            | Concurrent workers, crash after send and provider failure do not duplicate incident transitions; possible duplicate sends are documented (OPS-006).                          |
| Retention/restore produces false confidence            | Indexed bounded deletion, quota release, separate audit retention, explicit restore evidence and measured RPO/RTO                                                      | Deletion cannot cross scope; unverified/missing history cannot imply health; backup success cannot mark restore verified (OPS-004/008).                                      |
| Freeze causes lost security visibility                 | Freeze blocks configuration/actions but preserves ingestion, reads and audited emergency credential revoke                                                             | Freeze cannot prevent reporting/revocation or grant commercial authority; membership is checked before revealing freeze (OPS-002–004).                                       |

## Residual risks and rollout gates

A compromised authorized backend can lie, exfiltrate bits through bounded permitted observations and
fabricate new UUIDs until revoked. TLS/bearer authentication and schema tests do not prove host integrity.
A lost acknowledgement is ambiguous and must be retried unchanged. Deduplication is bounded to retention;
notifications may be delivered more than once after ambiguous send outcomes. DB administrators can modify
operational rows; only separately anchored audit history has its existing tamper-evidence guarantees.

An unavailable Warrior cannot report its own outage reliably; independent observation is required. No
restore drill, external probe, live credential, delivery provider or production integration is established
by OPS-001. OPS-001's tests prove schema acceptance/rejection only; OPS-002/003 runtime evidence is recorded below. Later tasks must mutation-check each
runtime control, run memory/least-privilege PG contracts and applicable load/outage scenarios, and attach
actual evidence in the status file. No production changes or real alert recipients are authorized by this design.

## OPS-002 control evidence

`services/platform-api/test/operations.test.ts` exercises session/role/tenant and
ancestor refusal, active owner/Product validation, unknown-field safe diagnostics,
version conflicts, lifecycle/tombstone behavior, scoped cursors, dependency cycles,
freeze and concurrent caps. `operations-store.db.test.ts` plus the shared store
contract exercise ancestor FKs, immutable identity, adapter isolation, rollback and
least-privilege deletion refusal. The contention driver tests requests beyond pool
capacity and exact successful-write/audit counts. Mutation checks are recorded in
the program handoff. These controls do not establish credentials, ingestion,
notification delivery, independent probes or any live application integration.

## OPS-003 control evidence

Credential service/store contracts and HTTP tests cover fresh MFA consumption and
replay, recovery-code/reflected-MFA refusal, revoked session, tenant/ancestor and
purpose/source mismatches, digest-only persistence, one-time response/metadata/log
separation, bounded TTL/active count, overlap, irreversible state, freeze emergency
revoke, failed audit rollback and disabled rollout. The real PostgreSQL contention
scenario uses separate MFA identities and more contenders than pool connections;
it also observes revocation waiting on a guarded verification callback before
refusing further use. Security mutation results belong in the status file.

These checks establish a guarded transaction primitive. They do not prove event
schema privacy, durable receipts, rate/event quotas, actual ingestion/revocation
races through a collector route, alerts or live integrations; those are later tasks.

## Dashboard control boundary

The application management portal reuses the session-authenticated inventory and
credential APIs; hiding or showing controls grants no authority. The server remains
responsible for organization membership, roles, expected versions, lifecycle, freeze,
fresh MFA and atomic audit. Browser contexts capture their organization and visit;
late responses cannot render credentials in a different context. Submitted factors
are cleared before awaiting requests. One-time secrets are not stored in browser
storage and are removed on dialog close/cancel, navigation and page exit. Browser
regression and deliberate-mutation evidence are recorded in the program handoff.

## OPS-005 health read boundary

Latest eligible heartbeat selection is transactional with committed evidence. Reports older
than 120 seconds at receipt or future-dated cannot refresh health; older occurrences and
equal-occurrence healthier ties cannot overwrite a failure. Duplicate receipt TTL cannot
resurrect health. Inactive ancestry and missing/expired state remain unknown; TTL expiry is
stale. Dependency states cannot promote health. All read paths verify live ops:read authority
before scope lookup and again on the transaction connection. Counts are historical assertions
with gaps and truncation, not availability measurements. Public readiness returns only a
bounded fixed-connection persistence result; raw diagnostics and arbitrary destinations never
enter it. Independent Warrior monitoring and optional-provider checks remain deployment work.

Manual triage slice: every read/mutation is organization scoped and checks current
session/membership inside the serialized organization transaction; integration keys
have no incident authority. Assignment rejects nonmembers and inactive users.
Reasons are fixed enums, with no arbitrary text/URLs/payloads. Concurrent opens
collapse to one active incident. Optimistic versions prevent lost responder updates;
resolved incidents cannot reopen. Audit failures roll back state. A bounded retained
record cap fails closed rather than dropping history. This does not establish any
automatic rule, maintenance suppression, notification delivery or pruning control.

### OPS-006 automatic evaluation and portal notification boundary

Rules admit only reviewed event types, finite thresholds/windows and runbook enums.
Counts derive from durable receipt timestamps and full scope. A stale/absent source
cannot trigger a healthy recovery. Persist evaluation/incident correlation and use
unique active rule keys to contain storms across workers/restarts. Maintenance
suppresses notification creation without rewriting health. Every configuration
mutation and incident transition is audited atomically. Portal destinations are
fixed user IDs, never addresses supplied by evidence. Claim fences prevent a late
worker from acknowledging a newer attempt; retry deadlines/caps bound outages.
Tests must cover wrong scope/role, freeze, audit rollback, duplicate evaluations,
maintenance, missing/stale recovery, retry fences and retention scope.

### OPS-008 posture boundary

Treat all imported scan/recovery results as unverified `admin_report` assertions.
Strict schemas exclude raw secret material, source context, filenames and URLs;
digests identify artifacts without fetching or verifying them. Server-derived scope,
immutable source snapshots, bounded quotas, active same-org assignees, monotonic
assessment time and atomic audit contain spoofing, overwrites, flooding and stale
confidence. A backup pass cannot count as a restore; successful restore assertions
require ordered timestamps and explicit integrity/application/audit check assertions.
Test authorization at both boundaries, archived/frozen scopes, changed retries,
audit failure, missing/failed checks, unknown fields, future evidence and stale data.

### Local GitHub collector

Treat the provider response as potentially secret-bearing and malicious. Allow only
reviewed GitHub paths on a fixed HTTPS origin, refuse redirects and arbitrary links,
preserve TLS/proxy settings, bound bytes/time/count, and project metadata before any
stdout write. Denial, pagination and malformed payloads cannot imply a completed or
clean scan. Never surface provider errors, raw bodies, token values or repository
source context. Verifying a commit and authenticating a local fetch do not attest
scan execution or elevate the later import beyond `admin_report`.

### Browser organization attention view

Reuse scoped server-authorized reads with bounded fan-out. Check current visit and
workspace before each batch and before rendering. Never let late responses reopen
an old workspace. Refuse auth failures rather than showing cached data; render other
read failures as unavailable. Label inventory/evidence truncation and snapshot counts.
No absent report, successful backup or zero visible finding count implies a verified
restore or complete security coverage. Navigation goes only to API-returned scoped IDs.

## Independent availability observer

A separate GitHub Actions workflow observes only the fixed public Warrior liveness
and persistence-readiness endpoints. There is no tenant-controlled probe target,
credential, redirect following, private-network access or infrastructure mutation.
Ten-second deadlines and 1 KiB response bounds include body reading. Fixed safe
results do not retain provider diagnostics. This observer does not write trusted
health evidence or incidents into Warrior. GitHub scheduling failure remains a
risk; missing/stale observations must not be interpreted as healthy. This limited
observer does not activate configurable application/network probes or audit
witnessing. See the independent availability deployment guide for rollout limits.

## Cloudflare deployment gateway preparation

The alternative Worker/Container boundary defaults to disabled traffic, no public
preview and one fixed container identity. It checks the configured HTTPS origin,
replaces client forwarding headers with edge-derived identity and emits fixed
503 refusals on errors. A reviewed, byte-bounded runtime binding allowlist excludes
migration-owner credentials and production/scanner bypasses. Normal application
production validation, authorization and database safeguards still apply. Secrets
are runtime bindings, not image build arguments. This preparation establishes no
Cloudflare deployment, live scanner path, worker fencing or automatic failover;
controlled staging and cutover acceptance remain required.

## Incident email notifications (24 October 2026)

| Threat                                               | Control                                                                                               | Negative-path evidence                                                                                 |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Incident details sent to an address nobody proved    | Recipient is the rule creator's account, looked up at send time; unverified address is never emailed  | Unverified creator: no message, notification stays pending and visible (`operations-email.test.ts`).   |
| Destination or content injected by a source or admin | No destination input anywhere; fixed plain-text template of codes/enums/IDs; envelope CR/LF refusal   | Event/rule destination fields rejected (existing); CR/LF recipient/subject refused before any request. |
| Misrouted provider request or credential exposure    | Fixed HTTPS endpoint, 32-hex account ID, redirect refusal, 10 s timeout, no body/token echo in errors | Bad account ID and removed redirect refusal are caught by mutation; no body/token echo is tested.      |
| False "delivered" state                              | Cloudflare success must list this recipient as delivered/queued and not permanently bounced           | Missing, other-recipient, bounced and malformed responses fail and are retried.                        |
| Provider outage or alert storm floods mail           | Existing outbox: one intent per transition, backoff 1–300 s, 72 h deadline, 2,000 retained intents    | Outage retries with backoff, then `failed`, then no further attempts.                                  |
| Silent source never alerts                           | A heartbeat rule breaches once its last report is 180 s stale; total silence is not "unknown"         | Healthy then silent component opens one incident after the window and resolves on fresh reports.       |

Residual: a provider timeout after acceptance can repeat a message; mail providers can
read message content (codes, severity and incident IDs only); a compromised mailbox
learns incident metadata. Email does not prove Warrior itself is up; the external
observers remain the independent check.

## Warrior probes (24 October 2026)

| Threat                                              | Control                                                                                                 | Negative-path evidence                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Tenant or event steers Warrior to a chosen URL      | Targets exist only in operator configuration; no API, rule, event or inventory field holds a URL        | Rule/event destination fields remain rejected; no route reads targets (`operations-probes.test.ts`).               |
| SSRF to private, loopback or cloud-metadata hosts   | HTTPS:443 DNS names only; every resolved address must be public; IP literals refused before connecting  | Loopback, metadata, private, CGNAT, ULA, NAT64, 6to4, mapped and IP-literal targets refused with zero connections. |
| DNS rebinding between check and connect             | The address check runs inside the connection's own lookup; mixed public/private answers are refused     | Mixed answers refused in both lookup forms; mutation to "any public" is caught.                                    |
| Redirect or cache hides an outage or reaches inside | Redirects never followed; non-200 and `Age` > 0 fail                                                    | 307, 500 and cached responses fail; only one request reaches the server.                                           |
| Resource exhaustion or data capture                 | 10 s deadline including body, 256 KiB cap, ≤10 targets, pass/fail stored, nothing logged                | Stalled and oversized bodies fail within the deadline; invalid UTF-8/JSON fails.                                   |
| Probe evidence mixed with backend reports           | Separate table and `probe` rule kind; heartbeat rules ignore probes and probe rules ignore heartbeats   | Healthy backend reports do not satisfy a probe rule; contract test keeps the two stores separate.                  |
| Probe written into another tenant's scope           | Runner checks the component's scope; memory parent check and PostgreSQL composite foreign key refuse it | Wrong environment or missing component is not recorded (reported as unrecorded).                                   |

Residual: a public target can still be slow or hostile within the fixed budgets; a
target's DNS can be changed by its owner to another public address; probes from Railway
share Railway's network fate, so the GitHub external observers remain the independent
check when Railway itself is down.
