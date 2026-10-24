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

## Rokela PDF availability

A second, separate workflow, **Rokela PDF external availability**, observes the Rokela PDF
application the same way: every ten minutes (offset from Warrior's run) or manually through
**Actions → Rokela PDF external availability → Run workflow**. It exists because Rokela PDF
and Warrior both run on Railway, so a Railway-wide outage would silence any check running
inside Warrior; this one runs on GitHub-hosted runners.

`tools/check-rokela-availability.mjs` makes two public read-only requests to the fixed origin
`https://www.rokelapdf.com`:

- `/api/v1/health` must answer 200 with a JSON body of exactly `{"ok":true}` (the app is up
  and its database answers), within 1 KiB.
- `/signin` must answer 200 directly, with an HTML body of at most 256 KiB containing the
  page title `<title>Rokela PDF Pro</title>`. Any redirect fails, so a sign-in redirect loop
  like the one of 24 October 2026 is caught, and so is an error page. The sign-in form itself
  renders in the browser; this check proves the page is served, not that a login succeeds.

The same limits as Warrior's observer apply: ten-second deadlines including the body,
credentials omitted, redirects refused, a nonzero cache Age fails, TLS verification on, and
logs carry only check names and passed/failed. Either failed check fails the job.

**Alerting:** a failed run is the alert. GitHub emails failed scheduled runs to the account
that created the workflow or last changed its schedule, if that account's
**Settings → Notifications → Actions** allows email for failed workflows. Confirm that setting
for the owner account after merging. The workflow sends no application messages, opens no
issues and imports nothing into Warrior; it does not replace Warrior's own heartbeat rules or
alert delivery. If the canonical Rokela PDF domain or page title changes, update the fixed
target and its tests together.

## Release observation

A separate **Warrior release observation** workflow runs on default-branch pushes
or manual dispatch. It checks liveness and persistence readiness, then compares
SHA-256 digests of the public HTML, CSS, portal and operations JavaScript against
the checked-out source. It waits up to six minutes for deployment to settle and
fails if the expected public release cannot be observed. An older healthy UI does
not pass the release comparison. Scheduled availability monitoring stays independent
and continues to check health even when a new deployment has failed.

The observer uses only fixed public destinations, omits credentials, refuses
redirects and cached responses, bounds transport/body time and reads at most 1 MiB
per asset. It prints fixed outcomes rather than provider response bodies. The
workflow never deploys, changes Railway settings or sends application alerts.

Matching public assets verifies those bytes and readiness at the observation time.
It does not identify the exact backend commit when multiple commits share the same
UI, establish authenticated acceptance, prove PDF integration or exercise restores.
After changing the canonical domain, review both observer scripts. On a slow build,
inspect the job and rerun it after deployment; do not remove the comparison to make
an older release appear successful. Newer pushes cancel obsolete release observers.
