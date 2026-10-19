# Application monitoring threat model

Status: **draft for OPS-001**. This identifies required controls, not controls already
implemented. Scope: inventory, ingestion, integrations, probes, alerts and incidents.

## Assets and boundaries

Protect integration credentials, operational evidence, application/tenant boundaries,
notification destinations, incident state, audit integrity and the availability of
both Warrior and connected systems. Browser clients, connected applications and
external providers are separate sources; a compromised connected app is in scope.
The collector, durable storage, workers, operator UI and monitored networks are
distinct boundaries. Monitoring authority must not imply licensing or remediation authority.

| Threat                                             | Required control                                                                   | Required negative/operational test                                                         |
| -------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Spoofed application, tenant or environment         | Bind identity and scope to credential; authorize every read/write                  | Credential for A cannot submit/read B or override scope in a body.                         |
| Stolen or replayed credential/event                | Rotation/revocation, bounded replay controls, scoped event IDs and conflict checks | Revoked credentials fail; exact retry is deduplicated; changed retry payload conflicts.    |
| Forged browser event treated as security fact      | Explicit provenance and separate schema/authority                                  | Browser errors cannot become confirmed malware or privileged audit events.                 |
| Secrets or document data in telemetry              | Strict allow-lists, bounded content checks, safe rejection diagnostics             | Rejected values appear in neither DB, logs nor response; permitted codes survive.          |
| Lost or ambiguously accepted events                | Commit before acknowledgement, source outbox, retry-safe ingestion                 | Crash/retry around commit causes no duplicate alert and no false durable acknowledgement.  |
| Event/alert flood or storage exhaustion            | Scoped quotas, bounded batches/queues, aggregation, retention, alert deduplication | One noisy integration cannot exhaust all tenants' capacity; drops/backlog are visible.     |
| SSRF and lateral network access through probes     | Ownership validation and explicit network/DNS/redirect policy                      | Refuse metadata, loopback/private and redirect/rebinding bypasses outside approved scope.  |
| Unauthorized rules, notifications or remediation   | Distinct permissions, audit, read-only initial rollout                             | Ordinary users cannot alter another app's rules, destinations or infrastructure.           |
| Alert-channel or database outage                   | Durable bounded retries, visible failures, independent Warrior monitoring          | Outage and recovery are exercised without blocking connected business flows.               |
| Restore creates false confidence or loses evidence | Recovery drills and explicit evidence/retention states                             | Backup success alone cannot mark recovery verified; restore integrity checks are recorded. |

OPS-001 must choose concrete mitigations and residual risks. Later tasks must map
each control to tests and record the mutation checks required by CLAUDE.md.
