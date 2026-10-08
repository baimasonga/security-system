# Recovery Procedures (V1)

Status: **procedures executable; not yet rehearsed.** The PostgreSQL adapters (ADR-005) and schema
exist; no restore drill has been run.

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
