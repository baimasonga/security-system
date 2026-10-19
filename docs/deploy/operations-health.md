# Component health and history (OPS-005)

Apply migration `0020_operations_health.sql`, then the managed application-role grants
and database-profile checks, before deploying the API. No existing evidence or
commercial access is changed. Set `OPERATIONS_HEALTH_ENABLED=true` together with
`OPERATIONS_INVENTORY_ENABLED=true` to expose read routes. Both default false in
source. Ingestion retains its independent rollout gate; do not enable production
collection or issue production credentials as part of this read rollout.

Applications → environment now shows **Reported health**. Component detail shows
**Recent event history**. Refresh explicitly to fetch current evidence. With the health
flag disabled the panel explains that reporting is not enabled. Outages show unavailable
evidence, never an empty healthy table. One-time credential behavior is unchanged.

## Meaning of health

Only typed backend heartbeat reports affect current state. Occurrence must be between
receipt minus 120 seconds and receipt; older/future reports remain historical evidence.
Latest occurrence wins, independently of arrival order. Equal-occurrence conflicts use
unavailable, degraded, unknown, healthy in descending precedence. An identical occurrence
cannot refresh receipt TTL. New UUIDs do not bypass ordering. The latest eligible assertion
persists transactionally with ingestion and survives API restarts.

A report becomes stale at 180 seconds after its original receipt. No retained eligible
report means unknown; inactive ancestry forces unknown. A dependency reporting unavailable
makes an active dependent unavailable; other missing/stale/degraded dependencies downgrade
an otherwise healthy dependent to degraded. Each response includes the own report and each
dependency's state. Recovery requires a later eligible observation. Backend assertions can
be fabricated by a stolen valid credential; these are not independent probes.

Existing pre-migration heartbeats are not backfilled into current state. Until the next
eligible heartbeat arrives, current health is unknown. Latest-report metadata expires with
its 30-day evidence retention and is deleted by the existing bounded maintenance worker.
Hourly component/type/outcome counts retain the collector's existing 90-day policy.

## Read APIs and gaps

Both routes require a live organization owner/admin session with `ops:read`:

- `GET /v1/organizations/{orgId}/operations/applications/{applicationId}/environments/{environmentId}/health`
- `GET /v1/organizations/{orgId}/operations/applications/{applicationId}/environments/{environmentId}/components/{componentId}/history`

History defaults to the last 24 hours using the server clock. Optional `from` and `to`
UTC timestamps must be supplied together, cover no more than 24 hours, end no later than
server time and start within the preceding 90 days. Counts are whole stored UTC receipt-hour
buckets overlapping the requested interval; boundary buckets can extend outside it.
The response identifies boundary alignment and caps output at 1,000 rows with `truncated`.
Narrow a truncated query. Missing hours remain gaps. Counts describe reported events,
not independent availability, successful checks or uptime percentages. No raw attributes,
credential identifiers or rejected payloads are exposed.

## Warrior readiness and external monitoring

`/healthz` remains process liveness. `/readyz` returns only `ready`/`unavailable` (200/503)
for the fixed internal persistence connection; production already requires PostgreSQL.
Checks coalesce, cache for one second and respond within a one-second check deadline.
A pending database query cannot fan out after timeouts. No secret, tenant identifier,
exception or dependency address is returned. In memory development mode persistence is
local and ready. This does not certify storage/scanners/mail or other optional providers.
Their readiness must be measured separately; event assertions are not substitutes.

Configure an independent external monitor, outside Warrior's process/database and failure
domain, to check HTTPS liveness and persistence readiness on the established deployment
origin. Route its alerts through an independently operated channel and test an outage.
This repository change creates neither an external monitor nor evidence of that exercise.
Network probes from inventory/events remain disabled. Never use arbitrary submitted URLs.
Maintenance windows and notification suppression are implemented with OPS-006 incidents.

## Rollback and verification

Disable `OPERATIONS_HEALTH_ENABLED` to hide read routes; keep the additive schema,
existing collector and bounded retention. No licensing, MFA or credential key rollback
is required. Derived heartbeat writes continue with collection while read routes are off.

Run `npm run check`, `npm run test:db`, `CHROMIUM_PATH=/path/to/chromium npm run test:portal`
and the disposable-database `tools/loadtest/operations-events.ts`. The load check now also
asserts 20 concurrent authenticated health reads and stale transitions on pool size two.
These are local integrity checks, not a production availability or capacity certification.

Repeat the security mutation checks with `DATABASE_URL=... node tools/mutation-check-operations-health.mjs`. The tool isolates its source copy and verifies unit plus PostgreSQL ordering/scope mutations without editing an active checkout.
