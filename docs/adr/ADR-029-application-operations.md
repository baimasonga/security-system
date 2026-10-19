# ADR-029: Cross-application operations and security monitoring

Status: **accepted design in OPS-001; OPS-002 inventory and OPS-003 credentials implemented, disabled by default; OPS-004 onward pending**.
Date: 19 October 2026. Trust-boundary change: **yes**.

## Context and baseline

Warrior needs to monitor multiple applications and systems. Reconciled against `87256b7`
and PR #15: Products are licensing catalog, client telemetry is privacy-filtered usage data,
and the Security Center is account/device oriented. Buffered telemetry cannot acknowledge
committed evidence. OPS-002/003 now add inventory and credentials; the event collector remains pending.
Business Admin provisioning and Rokela PDF's shared subscription/auth remain unchanged.

## Decisions

The normative [operations contract](../api/operations-contract.md) resolves OPS-001's decisions.
The [planned OpenAPI](../api/operations-planned.openapi.yaml) retains OPS-004 requests and responses. Implemented OPS-002 inventory and OPS-003
credentials moved to the live API contract with separate rollout flags.

1. **Inventory and authority.** Organization → application → environment → component. An active
   organization member owns the application, with criticality and optional active Product mapping.
   Immutable codes, versioned updates and terminal archive prevent attribution reuse. Separate
   `ops:*` permissions default to admin/owner only; no implicit licensing, membership, operator,
   remediation or cross-tenant authority. Reuse membership checks before freeze checks. Management
   mutations require reviewed reason codes and atomic audit. Freeze preserves reads/ingestion and
   emergency credential revocation, and blocks other management writes.
2. **Credentials.** Random 256-bit bearer secret and public credential ID per environment/purpose;
   SHA-256 verification material and timing-safe comparisons; secret returned once with no-store.
   Initial purpose `events:write`, source `backend_report`. TTL 1–90 days, at most two active
   credentials, rotation overlap 0–3600 seconds without extending old expiry. Transactional locks
   serialize ingestion with revocation. A lost issue response requires rotate/revoke, never secret
   recovery. Bearer authentication proves source attribution, not truth or freshness of its claims.
3. **Ingestion.** Nine strict version-1 event schemas with enums/bounded integers; no free text,
   scope overrides, severity, URLs, personal/document data or job/request identifiers. Preserve
   ADR-027; backend integration types never enter browser telemetry. Batches 1–100 and <=256 KiB,
   occurrence window 24 hours past/5 minutes future for new events. Store server receipt time and
   credential-derived scope/source. Commit before 200 acknowledgements. Dedup per scoped UUID and
   canonical content across rotation; changed retries are 409, exact old retries survive until
   30-day retention. Atomic batches and quota accounting; no exactly-once promise.
4. **Budgets and failure.** Collector/source limits, jittered retries, durable bounded source
   outbox, 429 backpressure and 503 on unavailable commits are specified explicitly. Monitoring
   must never block business transactions or consume commercial quotas. Raw operational evidence
   and dedup identities retain 30 days; aggregates 90, incidents 365, notification metadata 30;
   audit policy remains separate. Source drops/backlog and collector failure are visible.
5. **Health and probes.** Receipt-time heartbeat freshness, unknown/stale distinct from healthy;
   durable history and independent Warrior monitoring. Network probes remain disabled. Future
   probe deployment requires an ADR amendment, ownership proof, approved destinations, pinned DNS,
   TLS checks, no redirects/private/metadata access and an isolated budgeted worker. Inventory or
   events never become destinations to execute.
6. **Incidents and delivery.** Typed rules, one active incident per scoped rule/component, explicit
   open/acknowledged/resolved states, same-organization assignment and atomic audit/notification
   intent. Notification workers use fenced claims and bounded at-least-once delivery; duplicate
   sends remain possible after ambiguous provider responses. Only verified configured destinations,
   fake recipients in acceptance, no remediation authority. Incident routes are specified in OPS-006.
7. **Placement and rollout.** Independent `operations` package with audit/crypto/shared-types and
   telemetry-detector dependencies, auth/catalog checks injected by the composition root. New PG
   adapters use strict ancestor keys, app-role grants, contract/negative/mutation tests and applicable
   load checks. Task order is OPS-001 through OPS-008. Roll out disabled to a test organization first;
   rollback disables routes/workers and revokes credentials while preserving evidence and licensing.

## Alternatives and consequences

User sessions and license keys are rejected as collector credentials because their authority and
lifecycle are unrelated. HMAC request signing is deferred: random scoped bearer credentials over TLS,
durable IDs and strict replay/conflict limits supply the initial protocol without ambiguous signing
canonicalization. This does not resist a stolen active credential fabricating new event IDs.

Reusing the lossy telemetry sink is rejected because an in-memory buffer cannot promise durable
acknowledgement. Per-event audit chaining is also deferred to avoid serializing ingestion on a global
audit lock; operational evidence is committed separately, with privileged changes still audited.

No network probes in the initial milestone is a deliberate scope decision, not an unresolved safety
policy. Backend health reports must remain labeled as assertions. Public probe implementation, bespoke
per-application role delegation, additional event types and remediation need later reviewed changes.

## Evidence and limits

OPS-001 adds documentation, machine-readable planned schemas and contract-example tests only. These
are executable schema checks, not implemented authorization, storage, credentials, event ingestion,
alerting or a live Rokela PDF integration. Subsequent tasks must record runtime/PG/load/mutation evidence
in [the status file](../programs/operations-security-status.md) before claiming those controls exist.

## OPS-002 persistence refinement

A per-organization `operations_accounts` lock anchor serializes inventory writes,
including lifecycle, owner changes, caps and same-org dependency cycle checks.
This deliberately coarse lock subsumes descendant inventory locks until credential
and event tasks add their finer locks after the same anchor. All authority checks
inside a PostgreSQL transaction use its own connection. A contention test exposed
pool exhaustion when callbacks checked permissions through the outer pool; the
transaction-bound authority port removes that dependency. Audit append stays in
the same transaction; grants permit archival but no physical deletion. Rollout is
opt-in through `OPERATIONS_INVENTORY_ENABLED`, with no production changes here.

## OPS-003 credential implementation

Credential management and guarded backend verification reuse the organization lock
anchor, so inventory lifecycle, rotation and revocation serialize together. A
fresh authenticator factor is consumed outside that lock, then permission and live
session are rechecked on the transaction connection. Backend verification never
uses account/commerce authority. Unknown IDs use a dummy digest; plaintext appears
only in the committed issue/rotate response with no-store. Metadata is an explicit
allow-list, not a spread of the persistence record.

The internal rotated marker prevents repeated rotation of a predecessor. An active
overlap predecessor blocks a second rotation even if its successor was revoked.
Zero-overlap replacement of one of two independent active credentials preserves
the cap; positive overlap needs a free slot. Revocation ignores freeze/ancestor
activity but retains membership, fresh factor and atomic-audit requirements.
The new flag depends on inventory and MFA configuration. Source integration/event
validation and durable receipts remain OPS-004, not established by a verifier test.
