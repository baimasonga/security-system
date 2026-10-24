# Automatic operations alerts rollout

Deploy the checked source with `node tools/predeploy.ts`: migration 0023, application
role grants and database profile verification must succeed before starting the API.
Enable `OPERATIONS_AUTOMATION_ENABLED=true` only alongside inventory, ingestion,
health and incidents. Preserve existing credentials and MFA keys.

In Applications, select an active environment and component. Owners/admins can
create an event-count or heartbeat rule, evaluate it, disable it or place it in
maintenance. Rules are immutable definitions; disable an obsolete rule and create
its replacement. Notifications appear in the creator's authenticated portal and,
when email notifications are enabled (below), in their verified inbox.

Use synthetic inventory and a separately scoped events credential issued through
fresh MFA for acceptance. Verify a matching failure opens one automatic incident,
concurrent evaluations do not duplicate it, maintenance suppresses notifications and
fresh successful heartbeat evidence resolves it after the recovery window. Verify
both transition notifications and audit history. Revoke the test credential and
archive synthetic inventory afterward. Never send private documents or real alerts.

## Incident email (optional)

Email the rule creator when an automatic incident opens or resolves:

1. Configure one provider. For Cloudflare Email Sending, with a sending domain already
   verified in Cloudflare: `MAIL_PROVIDER=cloudflare`, `CLOUDFLARE_ACCOUNT_ID` (32 hex
   characters), `CLOUDFLARE_EMAIL_API_TOKEN` (a token limited to Email Sending),
   `EMAIL_FROM` (for example `Warrior <alerts@your-domain>`) and `PUBLIC_ORIGIN` (the
   exact Warrior HTTPS origin used in the email link). Resend remains supported with
   `RESEND_API_KEY`; Cloudflare is used only when `MAIL_PROVIDER=cloudflare` is set.
2. Set `OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED=true`. Startup fails unless automation
   and a complete provider are configured.
3. The rule creator must have a verified account email (request verification from the
   account page). Unverified creators receive nothing; their notifications stay pending
   and become `failed` after 72 hours.
4. Accept with a synthetic rule on a test component: stop its heartbeats, confirm one
   "incident opened" email after about four minutes (180 s stale plus the rule window),
   then resume them and confirm the "resolved" email. Then disable the synthetic rule.

The email holds only inventory codes, severity, runbook, incident ID, time and a link
to `PUBLIC_ORIGIN`. A provider timeout can occasionally repeat a message. Email
rollback: set `OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED=false`; portal notifications
continue and nothing is deleted.

### Watching an application that reports heartbeats

For each component that sends `component.heartbeat` (Rokela PDF's API, scanner and
converter components do, every minute), create a `heartbeat` rule with threshold 1.
A rule breaches when the latest report is unavailable/degraded, or when reports stop
for 180 seconds; it opens an incident once the breach lasts the rule window, and
resolves after fresh healthy reports for a full window. A component that has never
reported since the rule was created stays `unknown` and does not alert.

## Warrior probes (optional)

Warrior can check public pages itself every 60 seconds and alert through `probe` rules.
This catches failures an application cannot report, such as a sign-in page that
redirects in a loop while the application still sends healthy heartbeats.

1. In Applications, create one component per page to check (for example `public-site`
   and `signin` under Rokela PDF → production). Copy the organization, application,
   environment and component IDs from the portal.
2. Set `OPERATIONS_PROBES_ENABLED=true` and `OPERATIONS_PROBE_TARGETS` to a JSON array
   (at most 10 targets), for example:

   ```json
   [
     {
       "org_id": "org_…",
       "application_id": "opa_…",
       "environment_id": "ope_…",
       "component_id": "opm_…",
       "url": "https://www.rokelapdf.com/api/v1/health",
       "content_type": "json",
       "contains": "\"ok\":true"
     },
     {
       "org_id": "org_…",
       "application_id": "opa_…",
       "environment_id": "ope_…",
       "component_id": "opm_…",
       "url": "https://www.rokelapdf.com/signin",
       "content_type": "html",
       "contains": "<title>Rokela PDF Pro</title>"
     }
   ]
   ```

   Only public HTTPS names on port 443 are accepted; startup fails on anything else and
   the error names the field, never the value. A probe passes only on a direct 200 of the
   expected type, not from a cache, containing the expected text, within 10 seconds.

3. Create a `probe` rule (threshold 1) for each probe component. A failing probe breaches
   at once; probes that stop arriving breach after 180 seconds. The incident opens after
   the rule window and resolves after a full window of passing probes. With email
   enabled, the rule creator is emailed as for other automatic rules.
4. At startup Warrior logs `operations probes enabled for N target(s)` (a count only). The
   Applications → environment page's **Reported health** table shows each component's
   **Warrior check** result and **Last checked** time beside the application's own report;
   `—` means no check has been recorded for that component.
5. The log line `operations probe results not recorded` means a target's IDs do not
   match an existing component in that scope; fix the IDs. No target details are logged.

Probes run from the Warrior host, so they share its network: if Railway itself is down,
neither Warrior nor its probes report. Keep the GitHub external observers for that case.
Probe rollback: set `OPERATIONS_PROBES_ENABLED=false` and remove `OPERATIONS_PROBE_TARGETS`;
probe rules then see no fresh results and stay `breaching` until disabled, so disable
them too. Nothing is deleted.

Rollback: set `OPERATIONS_AUTOMATION_ENABLED=false` and redeploy. Keep migration,
rules, incidents, notification metadata and audit history; do not down-migrate or
delete records to roll back. This stops rule evaluation/delivery without changing
licensing, manual incidents or source authentication. External monitoring and
restore verification remain separate release gates.
