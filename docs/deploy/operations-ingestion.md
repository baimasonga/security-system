# Operations ingestion rollout and rollback

The collector is source-implemented and **disabled by default**. Local tests do
not establish production acceptance or a live Rokela PDF connection.

## Prerequisites and rollout

Apply migration `0019_operations_events` as the schema owner, then rerun app-role
grants/profile checks. New evidence rows require SELECT/INSERT/DELETE for indexed
retention; UPDATE is withheld. Counters and derived aggregates have bounded worker
CRUD. Preserve migrations 0017/0018 and the existing MFA/signing/licensing secrets.

After local/CI gates, exercise a staging tenant with inventory and credentials
already enabled. Explicitly enable `OPERATIONS_INGESTION_ENABLED=true` for that
staging service. The value is strict `true|false`; source default is false.
Both existing inventory/credential flags must also be enabled for bearer verification.
Issue a separate `events:write` credential with fresh MFA; never substitute a session
or customer license. Configure the sender through its secret store, not a URL/query.

POST JSON to `/v1/operations/events` with an HTTPS bearer and exactly `schema: 1`
and `events`. The live OpenAPI and content-free fixtures define all nine variants.
Preserve each event UUID and timestamp spelling across retries. Return 200 receipts
only after commit; duplicate receipts preserve their original server receipt time.
Do not interpret authenticated source assertions as independent availability proof.

Verify tenant/component isolation, secret-free logs, exact retry receipts, conflict
handling, revocation, request/day/storage limits and maintenance progress. Monitor
`http_requests_total` by route/status, `operations_events_total` by stored/duplicate,
and `maintenance_deleted_total` / maintenance errors. Labels never include tenants,
keys or source attributes. An empty interval is not proof of healthy service.

## Backpressure and retention

Per credential: sixty authenticated collector requests in a sliding sixty-second
window; duplicates and schema/conflict/quota refusals consume that request budget.
Only fixed request timestamps/counts persist on a client refusal, never payloads. A separate pre-auth IP budget
allows 120 requests/minute per collector route. Daily new-event limits use UTC days:
10,000/environment, 100,000/organization. Stored canonical bytes plus 512/event are
capped at 500 MiB/environment and 2 GiB/organization. Duplicates are not charged
again against event/storage budgets. Refuse excess; never evict evidence to make room.

The existing maintenance schedule releases storage and deletes expired identities
atomically: at most 25 eligible organizations per pass and 1,000 events per org,
plus bounded expired counter/aggregate metadata. Events and dedup identities last
thirty days; hourly component/type/outcome aggregates last ninety days. Retention
continues when ingestion is disabled. Unavailable maintenance can cause a storage
cap to refuse writes until cleanup succeeds. Report that backlog; do not bypass caps.

Senders must use a separate durable bounded outbox and unchanged IDs on retry;
that application-side outbox is OPS-007, not supplied by this collector change.
503/commit ambiguity is retryable and never a durable ACK. Only 429 carries
Retry-After. Generic 400/409/422 are local quarantine candidates; 401/403 require
configuration repair. Historical evidence ingestion does not refresh current
component health; the OPS-005 state machine remains pending.

## Rollback and evidence limits

Disable the ingestion flag first. Keep additive tables, credential digests, audit
history and normal retention. Never delete licensing state, rotate unrelated
secrets or drop tables as rollback. Re-enable only after the affected gate passes.

This change has local synthetic-tenant/HTTP/PostgreSQL evidence only. It configures
no production flag, live integration key, alert recipient or independent monitor.
An automatic deployment or healthy process does not establish authenticated live
collector acceptance, successful source delivery or a recovery drill.
