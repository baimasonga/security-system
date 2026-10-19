# Cross-application operations and security program

Date: 19 October 2026. Product direction: Bai Bureh Warrior should monitor and help
protect all of the owner's applications and systems. Rokela Business Admin is the
first integration reported by the owner; Rokela PDF is the second candidate.

This document records a roadmap, not a claim that its proposed APIs, credentials,
monitoring jobs or incident workflows already exist. Design proposals are recorded
in ADR-029. Implementation progress belongs in
[the status file](operations-security-status.md).

## Source baseline and evidence limits

The source review used commit `d61d350` on `claude/sleepy-carson-l0if1k`:

| Existing foundation            | Evidence                                                                                  | Boundary                                                                                                             |
| ------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Product catalog and licensing  | `packages/licensing`, `tools/sierra-catalog.ts`, `docs/deploy/sierra-business-rollout.md` | Catalog provisioning and development tests do not prove live acceptance.                                             |
| Account/device Security Center | `services/platform-api/src/security-center.ts`                                            | Describes the signed-in person's account, roles and devices, not a fleet operations dashboard.                       |
| Client telemetry               | `routes/organizations.ts`, `packages/telemetry/src/firewall.ts`                           | User-authenticated; only `app.started`, `feature.used`, `app.error`; no trusted application/environment attribution. |
| Telemetry storage              | `db/pg-telemetry-sink.ts`, migration `0001_init.sql`                                      | Product telemetry is best-effort and may be lost. Existing security records are written synchronously.               |
| Operational metrics            | `metrics.ts`, `routes/admin.ts`                                                           | Warrior's own process metrics; in-memory counters need external collection for history.                              |
| Health endpoint                | `services/platform-api/src/app.ts`                                                        | `/healthz` reports process health; it does not prove dependency readiness.                                           |
| Recovery procedures            | `docs/runbooks/recovery.md`                                                               | Restoration objectives are targets; the document says drills have not been rehearsed.                                |

Existing identity, MFA/passkeys, audit, privileged operations, privacy filters and
CI security checks are foundations to reuse. Verify their current implementation
and configuration rather than relying on older README status statements.

## Product scope

Model organization → application/system → environment → component. Components may
be web services, databases, storage, workers, scanners, desktop clients or external
providers. Record ownership, criticality and dependencies. A licensing Product may
be linked to an application; it is not a substitute for environment/component
inventory. An internal system may need monitoring without a commercial license.

The organization-wide view should answer: what needs attention, which systems are
affected, who responds, what evidence supports the finding, and what happens next.
Each application also needs an isolated detail view. Licensing, monitoring and
remediation permissions must remain distinct.

## Mandatory invariants

- Derive organization, application, environment and allowed source from the
  integration credential. Refuse mismatching body fields. Never use a customer
  license key or a long-lived operator session as a monitoring credential.
- Issue separate, revocable, rotatable credentials per application/environment and
  purpose. Store verification material safely; never display a secret again after
  issuance. Exact authentication and rotation mechanisms must be specified in ADR-029.
- Separate untrusted browser reports, authenticated backend observations and
  independent probes. Authentication proves the source, not the truth of its claims.
- Strictly validate versioned event schemas. Do not ingest document contents,
  filenames, recipient addresses, passwords, private access URLs, arbitrary HTTP
  bodies or unrestricted stack traces. Extend the allow-list deliberately; do not
  weaken ADR-027 to make new events fit.
- A durable acknowledgement means committed ingestion, not insertion into an
  in-memory buffer. Support bounded at-least-once delivery, scoped event identity,
  deduplication and conflict detection. Do not promise exactly-once execution.
- Monitoring outages must not stop business transactions, upload/download access,
  conversions or existing license policy. Use a bounded outbox with retry/backoff;
  surface backlog, dropped low-priority events and delivery failures.
- Credential changes, rules, incident actions and any remediation need authorized,
  audited transitions. Keep audited state changes and their audit entries atomic.
- Start read-only. Infrastructure credentials must be least-privileged and isolated.
  Remediation is a later explicit workflow with scoped authority, approvals where
  appropriate, expiry, rollback instructions and audit evidence.
- Health checks must not become SSRF or internal-network scanning capabilities.
  Specify ownership verification, destination restrictions and redirect/DNS policy
  before implementing probes. Never execute a URL taken from an ingested event.
- Keep Warrior's own health visible through an independent monitor. Define event,
  metric and incident retention; audit retention follows its existing separate policy.

## Delivery tasks

Dependencies are mandatory; finish a vertical slice with negative-path tests before
starting the next. Proposed names below are concepts, not existing endpoint contracts.

| Task                                             | Depends on       | Deliverable and completion criteria                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------ | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OPS-001 — Contracts and threat model             | None             | Reconcile the source baseline; finalize ADR-029 and threat model; specify ownership/RBAC, credential lifecycle, versioned events, acknowledgements, deduplication scope, quotas, retention, probe policy and failure semantics. Add illustrative safe payloads, error cases and the planned OpenAPI contract without representing unimplemented routes as live. Resolve open decisions in the ADR. |
| OPS-002 — Application inventory                  | OPS-001          | Application/environment/component records, optional Product mapping, owner and criticality; authenticated CRUD and read views; tenant isolation, deleted/disabled behavior and audited mutations. Migrations, app-role grants, memory/PG contract tests and OpenAPI implementation match.                                                                                                          |
| OPS-003 — Integration credentials                | OPS-002          | Scoped issuance, verification, rotation and revocation; one-time secret delivery; negative tests for wrong tenant/application/environment/purpose, revoked credentials and privilege escalation; secrets absent from logs and responses. No production credentials required for local acceptance.                                                                                                  |
| OPS-004 — Durable event ingestion                | OPS-003          | Typed backend events, trusted attribution, occurrence/receipt timestamps, bounded batches, committed acknowledgements, retry-safe deduplication and conflicts, retention/quotas. Test crashes/retries, concurrency, duplicates, malformed/PII payloads, clock skew, source spoofing and DB failure. Track rejected events without retaining rejected values.                                       |
| OPS-005 — Health and history                     | OPS-002, OPS-004 | Separate liveness/readiness; dependency statuses, heartbeats with explicit stale/unknown states; historical aggregates and monitoring of Warrior itself. Network probes satisfy the SSRF threat model and fixed budgets. Process restarts do not erase all operational history.                                                                                                                    |
| OPS-006 — Alerts and incidents                   | OPS-004, OPS-005 | Rules with evaluation windows, deduplication, maintenance suppression, severity, affected components and runbooks; incident open/acknowledged/resolved lifecycle, assignment and audited changes. Durable notification outbox with retries and visible failures; test alert storms and delivery outages. Test notifications use fake/local recipients.                                             |
| OPS-007 — Rokela PDF integration                 | OPS-004, OPS-006 | Implement the integration brief: scoped staging credentials, safe server events, bounded outbox, health observations and one simulated failure → event → alert → incident → recovery flow. Verify isolation from Business Admin. Preserve Rokela's current auth and one subscription covering PDF, transfers and short links.                                                                      |
| OPS-008 — Security posture and recovery evidence | OPS-006          | Read-only dependency/secret scan result integrations; prioritized findings with owner and remediation state. Backup status and restore-exercise evidence, measured RPO/RTO, rollback records and escalation runbooks. A backup-success badge must not imply a successful restore.                                                                                                                  |

## Definition of done for every task

1. Code, API contract, ADR/threat model changes and status documentation agree.
2. New security controls have negative tests and the mutation checks required by
   CLAUDE.md. Database changes include least-privilege grants and adapter contracts.
3. `npm run check` passes; applicable `npm run test:db` and load/soak checks pass.
   Record commands, outcomes, runtime versions and any limits of the evidence.
4. Existing licensing, privileged operations and Business Admin acceptance remain
   intact. Monitoring cannot grant or revoke commercial access implicitly.
5. Record a bounded rollout, rollback and configuration guide. Use staged test
   environments and fake providers before requesting production credentials.
6. Update the status file with commit/PR links and the exact next action. Distinguish
   implemented, locally verified, staging verified and production verified.

## Deferred work

Automatic remediation, full SIEM replacement, custom vulnerability detection engines,
endpoint antivirus agents and changes to customer billing/authentication are outside
the first operations milestone. Integrate existing specialist tools before rebuilding
their engines. Thresholds in examples are illustrative until tuned against evidence.
