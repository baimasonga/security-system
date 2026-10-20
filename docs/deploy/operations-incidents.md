# Manual incident management rollout

This is the first OPS-006 slice. It provides human-operated incident records and
dashboard actions. It does not evaluate alert rules, send notifications, execute
runbooks, change reported health, or affect licenses/devices. Those remaining
OPS-006 paths are not enabled by this setting.

Apply migration `0022_operations_incidents.sql`, then run `npm run db:grants` and
`npm run db:check`. The application role gets SELECT/INSERT/UPDATE on the new table;
it cannot delete/truncate incident history or remove database guards. Keep existing
keys and integration settings unchanged. Set `OPERATIONS_INCIDENTS_ENABLED=true`
and `OPERATIONS_INVENTORY_ENABLED=true` only after local acceptance and deployment
readiness checks. Both source flags default false; ingestion and health retain their
independent flags. No provider token, email destination or paid resource is needed.

Open **Applications → application → environment → Incidents**. Choose an active
component and severity, then **Open incident**. **Manage incident** offers assignment,
acknowledgement and resolution, each with an explicit reason. Resolved rows remain
visible and immutable. Repeated opens reuse the active manual incident for that
component. A new explicit open after resolution creates a new manual record. This
is human triage, not confirmation that a backend report or independent probe exists.

Only owners/admins currently have `ops:read` / `ops:manage_incidents`. A current
session and same-organization active assignee are required server-side. Cross-scope
IDs return 404; stale revisions return 409. Refresh before retrying a stale edit.
Privileged freezes reject mutations but permit authorized reads. Deactivated
inventory refuses new incidents; responders can still close existing incidents.

The slice bounds retention storage to 1000 records per environment and lists at most
100 per request with identifier pagination. There is no purge implementation yet:
reaching the cap refuses another open without deleting history. Implement the
contract's bounded 365-day pruning before describing OPS-006 retention as complete.
A completed manual workflow does not establish automatic alerting or notification
acceptance. Do not send production test alerts to real recipients.

Rollback: set `OPERATIONS_INCIDENTS_ENABLED=false`; retain the table, audit records,
existing source flags and keys. This hides the workflow without deleting evidence.

Verification commands (disposable PostgreSQL only):

```sh
npm run check
DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres npm run test:db
CHROMIUM_PATH=/usr/bin/chromium npm run test:portal
DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres node tools/loadtest/operations-incidents.ts
NPM_CONFIG_CACHE=/workspace/.npm-cache DATABASE_URL=postgres://postgres@127.0.0.1:55432/postgres CHROMIUM_PATH=/usr/bin/chromium node tools/mutation-check-operations-incidents.mjs
```

The mutation runner uses an isolated source copy with its own npm workspace links.
It installs from the lockfile/offline cache and requires assertions to kill each
mutation; compile/setup failures do not count. Omit NPM_CONFIG_CACHE to use npm's
default cache on other machines. The load scenario uses real loopback HTTP, an
isolated fsync-on schema and a two-connection pool. It asserts exact deduplication,
stale-edit and audit outcomes; its duration is not a production capacity benchmark.
