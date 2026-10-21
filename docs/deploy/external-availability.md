# Independent Warrior availability observation

GitHub Actions runs **Warrior external availability** approximately every ten
minutes, or manually through **Actions → Warrior external availability → Run workflow**.
The workflow is independent of Warrior's process, database and notification outbox.
It needs no Railway, database, integration or email credential. It makes two public
read-only requests to the fixed Warrior HTTPS origin: `/healthz` for liveness and
`/readyz` for persistence readiness. No repository/user input can supply a target.

Each request has a ten-second deadline including body reading. Redirects, non-200
status, non-JSON or unexpected status bodies, bodies above 1 KiB and a nonzero
cache Age fail the check. Requests omit credentials and ask caches not to reuse
responses. TLS verification remains enabled. Logs contain only the check names
and passed/failed results, never provider bodies, headers or raw exceptions.
Either failed check fails the job. Liveness passing cannot hide failed readiness.

A GitHub run is observation evidence at that time, not an ongoing healthy badge.
Schedules can be delayed or missed; GitHub can disable scheduled workflows in
inactive public repositories. Review Actions for stale/missing runs and configure
your personal GitHub workflow notifications as appropriate. This workflow creates
no issues, sends no application messages and configures no notification recipient.
GitHub account notification delivery is separate from Warrior's alert delivery.

This is a basic outside-in HTTP observer, not a multi-region uptime SLA, alert
paging service, audit witness, authenticated synthetic conversion or restore drill.
It does not import health or incident records into Warrior, mark dependencies
healthy, follow redirects, inspect private files or execute remediation. A green
run does not establish that Rokela PDF is connected or working.

To suspend observation, disable this workflow in GitHub Actions. There is no
production application flag or data migration to roll back. If the permanent
Warrior domain changes, review and change both fixed targets in the script and
its tests; do not replace them with arbitrary environment-supplied destinations.
