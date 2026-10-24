# Warrior feature ideas (backlog)

Date: 24 October 2026. Status: ideas only, nothing here is approved, specified or built.
Each item needs the usual spec/ADR/threat-model work (see [CLAUDE.md](../../CLAUDE.md))
before implementation. Effort is a rough guess: S = days, M = about a week or more.

Context: Warrior already has inventory, scoped integration credentials, durable event
ingestion, heartbeat health and history, typed alert rules, incidents, portal and email
notifications (opt-in), operator-configured HTTPS probes (opt-in), security findings and
recovery evidence, and licensing for Rokela PDF and Sierra Business.

## Recommended order

1. **TLS certificate and domain expiry alerts** (#1): small; an expired certificate or
   domain takes a whole site down.
2. **Telegram alerts** (#4): small; faster than email on a phone.
3. **Deploy markers on incidents** (#2): both Rokela PDF outages on 24 October 2026 were
   caused by deployments.

## Catch problems before users do

| #   | Feature                           | Value                                                                                                                                                   | Effort |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 1   | TLS certificate and domain expiry | Probes already open HTTPS connections; record the certificate's expiry date and alert 14 and 3 days ahead. Optionally check domain registration expiry. | S      |
| 2   | Deploy markers on incidents       | Ingest Railway/GitHub deployment events; show "started 2 minutes after deploy X" on the incident timeline.                                              | M      |
| 3   | Uptime and response-time history  | Keep each probe result (bounded retention); monthly availability % and latency per application; spot slow degradation before an outage.                 | M      |

## Respond faster

| #   | Feature                        | Value                                                                                                                             | Effort |
| --- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 4   | Telegram alerts (or webhook)   | Free, instant phone alerts through the same fenced notification outbox as email.                                                  | S      |
| 5   | Escalation when unacknowledged | If an incident is not acknowledged within N minutes, notify a second responder. Needed once there is staff.                       | S–M    |
| 6   | Daily or weekly digest email   | One message with uptime, incidents, open findings and upcoming expiries, so the dashboard need not be opened to know all is well. | S      |

## Security and maintenance on autopilot

| #   | Feature                             | Value                                                                                                                                                 | Effort |
| --- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 7   | Scheduled Dependabot import         | Server-side, read-only GitHub collection of security alerts into owned findings (today it is operator-local). Needs a scoped token stored in Warrior. | M      |
| 8   | Credential and key expiry reminders | Reminders before integration credentials, Cloudflare tokens and provider API keys expire or are due for rotation.                                     | S      |
| 9   | Public status page                  | For example `status.rokelapdf.com`: current status and incidents from Warrior probes; reduces "is it down?" support messages.                         | M      |

## Grow beyond monitoring

| #   | Feature                           | Value                                                                                               | Effort |
| --- | --------------------------------- | --------------------------------------------------------------------------------------------------- | ------ |
| 10  | Connect Sierra Business OS        | Third monitored application, following the Rokela PDF integration pattern.                          | S–M    |
| 11  | Licence and subscription overview | Active customers, renewals, expiring licences and revenue trend for Rokela PDF and Sierra Business. | M      |

## Notes

- Probe-related items (#1, #3, #9) touch `services/platform-api/src/operations-probes.ts`
  and `integrations/probe-http.ts`; coordinate with any in-flight probe work first.
- New outbound providers (Telegram, webhooks, registrar lookups) are trust-boundary changes:
  fixed endpoints, no destinations from events or tenants, and negative-path tests.
