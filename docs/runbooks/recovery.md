# Recovery Procedures (V1)

Status: **synthetic logical restore rehearsed; production recovery unverified.**
The isolated PostgreSQL exercise checks the full migration ledger, restored login,
application records and audit integrity. It does not establish production backup
coverage, point-in-time recovery (PITR), key recovery or production RPO/RTO.

| Scenario                                | Procedure                                                                                                                                                                                           | Recovery objective (target, to validate)           |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Bad deploy                              | Redeploy previous image. Schema changes are forward-only and expand→migrate→contract, so the previous app version must keep working against the new schema                                          | RTO 15 min                                         |
| Database loss/corruption                | Restore latest base backup + WAL to a point before the fault (PITR); verify `schema_migrations`; run `GET /v1/admin/audit/verify`; reconcile leases (below)                                         | RPO ≤ 5 min (WAL archiving), RTO 2 h               |
| Signing key unavailable (KMS outage)    | Signing fails closed (`internal`, no lease issued). **Existing leases keep working offline until `exp`**; customers are not locked out of documents. Restore KMS access or activate the standby key | Customer impact: no new activations/refreshes only |
| Audit chain break                       | Incident-response §D                                                                                                                                                                                | —                                                  |
| Lost operator access                    | Break-glass account (Milestone 6); until then a second operator performs `bootstrapPlatformAdmin` out of band                                                                                       | —                                                  |
| Mass device re-activation after restore | Devices re-activate idempotently (same device key ⇒ same slot); challenge endpoint is rate limited; expect a refresh spike — scale or stagger via `refresh_after` jitter (future)                   | —                                                  |

Principle (invariant): **a platform outage or licensing failure never deletes or
locks customer documents.** Clients degrade to documented states; they do not
destroy data.

Backups must be encrypted, access-controlled, and restore-tested at least
quarterly; the first restore drill is a launch prerequisite.

## Repeatable synthetic exercise

The **Warrior synthetic recovery exercise** GitHub Actions workflow runs weekly,
on relevant changes and manually. It creates disposable PostgreSQL 16 and 17 databases
with fsync enabled and synthetic accounts only. `tools/restore-drill-local.ts`
exports a consistent snapshot, restores it into a separate database, and checks:

- Every migration identity and checksum matches the checked-out source.
- The pre-snapshot account can log in and authenticate a new session; that session
  can read the recovered application finding.
- Incorrect credentials and the post-snapshot account cannot log in.
- Post-snapshot records are absent and audit verification passes before and after
  the restored application's authentication operations.

The emitted duration covers restore and validation on this small fixture, not
production incident recovery. `productionBackupVerified` remains `false`.
The local tool requires the disposable container and fixed loopback port shown in
`.github/workflows/recovery-exercise.yml`; it is not a production restore CLI.

## Production rehearsal acceptance

Before a rehearsal, record a named operator, source project, isolated destination,
backup identifier/recovery point, source deployment SHA, expected migration ledger,
and an approved maintenance/test window. Confirm the actual backup retention and
PITR entitlement in the provider account; a paid plan alone is not evidence of
five-minute RPO. Do not restore over the live project for a rehearsal.

Keep the destination private and prevent outbound effects before starting any
application process. Restored outboxes, sessions and integration credentials are
real data: disable email, event dispatch, probes and scheduled jobs, deny outbound
provider access, and exclude public traffic. Store exports only in approved
access-controlled encrypted storage, never in GitHub artifacts or chat.

Use the deployment version matching the recovery point. Before applying new
migrations, compare the restored ledger to that version. Validate role grants and
private-schema access with the runtime role, then check audit chains. Compare
against independently retained witness manifests when available; chain consistency
alone cannot prove a privileged actor has not rewritten history. Do not substitute
manifests generated from the restored database for external evidence.

Validate authentication including MFA and a representative authorized application
read using designated test accounts, without bypassing account protections. Confirm
required encryption/signing keys are recoverable through their separate secret
management process; a database backup alone does not contain that capability.
Reconcile revoked sessions, integration credentials and device leases against the
recovery point before any real cutover: a restore can resurrect old authority.

Record UTC incident/reference time, selected recovery point, restore start, and
completion of all acceptance checks. Measure RPO from the reference time to the
latest recovered committed business record, and RTO from the agreed incident start
to usable service. Retain metadata/results and reviewer sign-off, not row contents
or credentials. Mark failed or unperformed checks explicitly; never derive
production success from the synthetic workflow. Remove the isolated destination
under the approved data-retention policy after evidence review.
