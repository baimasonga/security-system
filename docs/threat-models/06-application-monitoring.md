# Application monitoring threat model

Status: **accepted design for OPS-001; required runtime controls remain unimplemented**.
19 October 2026. Normative limits/protocol: [operations contract](../api/operations-contract.md).
Scope: inventory, integrations, ingestion, health history, alerts and incidents; read-only first milestone.

## Assets and boundaries

Protect integration credentials, operational evidence, application/tenant boundaries, notification
destinations, incident state, audit integrity and availability of Warrior and connected systems.
Browser clients, connected backends and independent observers are distinct sources. A compromised
connected backend and a stolen active integration credential are in scope. Collector, durable store,
workers, account UI, notification provider and monitored networks are separate boundaries. Monitoring
authority must never imply commercial entitlements, infrastructure credentials or remediation authority.

| Threat                                                 | Chosen control                                                                                                                                         | Required implementation/operational test                                                                                                                                     |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant/application/environment spoofing                | Derive scope/source from scoped credential row; strict unknown-field rejection; component ancestor checks; separate `ops:*` permissions                | A credential cannot supply another scope or reference another environment's component; every read/mutation denies another tenant (OPS-002–004).                              |
| Privilege escalation through Product/operator identity | Optional Product mapping has no auth meaning; operators get no new tenant bypass; no licensing imports in operations                                   | Member/operator/credential cannot gain membership, license, rule or remediation authority (OPS-002/003).                                                                     |
| Secret theft or reuse after rotation                   | One-time no-store secret, SHA-256 digest, timing-safe dummy comparison, TTL, bounded overlap, transactional revocation                                 | Secret absent from logs, metadata and repeated issuance reads; no DB plaintext; old credential stops at expiry/revoke and rotation cannot extend it (OPS-003).               |
| Ingestion/revocation race                              | Parent-to-child locks, credential status rechecked under ingestion transaction; no cached authority on commit                                          | Revoke wins → refusal; ingest wins → one committed receipt; deadlock retry cannot bypass revocation (OPS-003/004).                                                           |
| Replay/changed retry or false acknowledgement          | Scoped UUID + canonical hash, 30-day identity retention, dedup before quota, atomic batch, commit before 200                                           | Crash before/after commit, concurrent retry/rotation, reordered JSON, changed payload and duplicate-ID batch conflict; DB failure returns no success (OPS-004).              |
| False evidence from compromised backend                | Immutable `backend_report` provenance; server-owned severity, no claimed independent-probe/audit authority                                             | Browser report cannot impersonate backend; backend malware assertion is never labeled platform-confirmed; future source types require review (OPS-004/005).                  |
| PII, file content, private links, covert channels      | Exact enumerations/numeric bounds, structural ID/time validators, ADR-027 checks, no arbitrary names/job correlations; fixed safe diagnostics          | Unknown fields rejected; filenames/recipients/tokens/paths never reach DB/logs/errors; unknown field names are not reflected (OPS-004).                                      |
| Quota/storage or alert flood                           | Credential request/IP limits, atomic env/org event/storage caps, bounded batches/outbox, receipt-time rule windows, unique active incidents            | Concurrent submissions cannot exceed quota; duplicates charge once; one noisy environment cannot consume another's budget; storm produces one active incident (OPS-004/006). |
| Monitoring outage damages business work                | Durable bounded source outbox outside business transaction; jitter/retry classification; 503 commit failure                                            | Collector outage fills bounded queue, exposes drops/backlog, and does not fail conversion/upload/download/license behavior (OPS-004/007).                                    |
| SSRF, metadata access and lateral scanning             | No network probes implemented initially; reject event/inventory destination fields; future isolated egress/DNS/ownership policy requires ADR amendment | Submitted URLs never execute; future probes test private/loopback/link-local/mapped IPv6, DNS rebinding, redirects and resource exhaustion before enablement (OPS-005).      |
| Stale/absent data presented as healthy                 | Receipt-time freshness, explicit unknown/stale, persisted history, independent Warrior monitoring                                                      | Missing/stale heartbeat and restart gaps cannot be healthy; maintenance suppresses notifications without changing health truth (OPS-005).                                    |
| Unauthorized rules/incidents/destinations              | Separate permissions, same-org assignee, verified destinations, mandatory reason and atomic audit                                                      | Ordinary member cannot modify, cross-org assignee denied, audit failure rolls back, event cannot choose a destination (OPS-006).                                             |
| Duplicate notification or provider outage              | Transactional outbox, fenced worker claims, 72-hour bounded retry, stable incident ID, visible failed state                                            | Concurrent workers, crash after send and provider failure do not duplicate incident transitions; possible duplicate sends are documented (OPS-006).                          |
| Retention/restore produces false confidence            | Indexed bounded deletion, quota release, separate audit retention, explicit restore evidence and measured RPO/RTO                                      | Deletion cannot cross scope; unverified/missing history cannot imply health; backup success cannot mark restore verified (OPS-004/008).                                      |
| Freeze causes lost security visibility                 | Freeze blocks configuration/actions but preserves ingestion, reads and audited emergency credential revoke                                             | Freeze cannot prevent reporting/revocation or grant commercial authority; membership is checked before revealing freeze (OPS-002–004).                                       |

## Residual risks and rollout gates

A compromised authorized backend can lie, exfiltrate bits through bounded permitted observations and
fabricate new UUIDs until revoked. TLS/bearer authentication and schema tests do not prove host integrity.
A lost acknowledgement is ambiguous and must be retried unchanged. Deduplication is bounded to retention;
notifications may be delivered more than once after ambiguous send outcomes. DB administrators can modify
operational rows; only separately anchored audit history has its existing tamper-evidence guarantees.

An unavailable Warrior cannot report its own outage reliably; independent observation is required. No
restore drill, external probe, live credential, delivery provider or production integration is established
by OPS-001. Tests currently prove schema acceptance/rejection only. Later tasks must mutation-check each
runtime control, run memory/least-privilege PG contracts and applicable load/outage scenarios, and attach
actual evidence in the status file. No production changes or real alert recipients are authorized by this design.
