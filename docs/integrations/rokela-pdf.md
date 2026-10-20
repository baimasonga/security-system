# Rokela PDF — second application integration brief

Status: **source adapter implemented and locally accepted; production not connected**. Depends on OPS-004/006; tracked
as OPS-007 in [the program](../programs/operations-security.md).

## Inventory and scope

Application code: `rokela-pdf` (OPS-001 accepted contract). Register production
and a separate staging environment. Components: web app/API, PDF converter, ClamAV,
database, object storage and email worker/provider. Preserve the existing shared
subscription for PDF, file transfer and short links, and existing authentication.
Monitoring must not silently migrate identity, billing or plan authority.

The current deployment uses Railway, Supabase and Cloudflare storage/email. The main
public address is `https://www.rokelapdf.com`; public short URLs use
`https://rokelapdf.com`. Private converter/scanner addresses must stay private.
Resolve current deployment settings during authorized rollout; do not copy credentials
or private file/request/share links into this document.

## Candidate backend events

These backend names/attributes are specified in the [OPS-001 contract](../api/operations-contract.md) and planned OpenAPI. They are not implemented telemetry endpoints; browser telemetry remains unchanged.

| Event                         | Safe attributes to specify                              | Intended use                                                                     |
| ----------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `upload.failed`               | stage, enumerated reason, duration, bounded size bucket | Detect failing uploads and storage problems.                                     |
| `conversion.failed`           | source/target type, reason code, timeout, duration      | Detect converter failures and resource pressure.                                 |
| `scanner.unavailable`         | failure code, queue age/count                           | Detect quarantine backlog without bypassing scanning.                            |
| `malware.detected`            | enumerated verdict; no file contents/name               | Investigate threats without collecting user documents.                           |
| `email.delivery_failed`       | provider, reason code, attempts, queue age              | Detect delayed or exhausted delivery. Provider acceptance is not inbox delivery. |
| `request.submission_received` | file count, processing state                            | Operational activity; no submitter name/email.                                   |
| `link.abuse_reported`         | category, processing state                              | Triage reports; do not forward the private link or report free text.             |
| `workspace.role_changed`      | allowed role transition and result                      | Security review; use only approved opaque/pseudonymous references.               |

The accepted version-1 envelope contains schema, UUIDv4 event ID, component ID, occurrence time, type and strict attributes. Warrior assigns receipt time, scope and backend-report provenance. Severity is server-owned. Request/job/person/document correlation IDs are excluded in version 1; arbitrary URLs, headers, bodies, stack traces and email addresses are not permitted. Heartbeats use the separately specified `component.heartbeat` event and are not independent probes.

## Delivery and credentials

- Use a server-side adapter and a separate credential per environment. No operator
  token, platform signing key or collector secret belongs in the browser.
- Capture allow-listed events through a bounded durable outbox with retry/backoff
  and visible backlog. Persist event identity across retry and process restart.
- A Warrior outage must not fail file transfers, conversions or link resolution.
- Add real dependency readiness checks and stale-heartbeat detection. Do not infer
  converter, scanner or database health from a successful web-page response.
- Keep frontend reports separate and untrusted. Use read-only provider integrations;
  remediation requires a later explicit authorization design.

## Acceptance and rollout

1. Local tests use fake collectors/providers and prove no tokens, files, recipients
   or private URLs leave the source telemetry boundary.
2. In staging, exercise a controlled conversion failure and scanner outage; verify
   source event → durable receipt → deduplicated alert → incident → recovery.
3. Test duplicate delivery, changed-payload conflict, revoked/wrong-environment
   credentials, collector outage and source restart. Confirm Business Admin remains
   isolated and existing application flows work during monitoring failure.
4. Verify provider permissions, delivery credentials, authorized alert destinations,
   retention, rollback and independent monitoring of Warrior before production.
5. Record actual staging/production observations in the status file. Do not send
   real alerts or change production configuration just to satisfy a local test.

## Implemented source adapter and isolated acceptance

The `baimasonga/rokelapdf-online` source adds server-only conversion/scanner
observations and a bounded PostgreSQL outbox, fixed to Warrior's collector origin.
It preserves Supabase identity and the one shared workspace subscription. See that
repository's `docs/warrior-monitoring.md` for exact configuration, event privacy,
fencing/retry budgets, operator backlog UI and rollback.

Its optional cross-repository test provisions synthetic local MFA/credentials and
drives actual conversion failure → collector outage/restart → durable receipt →
concurrent automatic incident deduplication → fresh conversion recovery → resolved
incident/portal notifications. Private test schemas and fake transport/providers are
used. This is not live staging or production acceptance. A fresh-MFA issued scoped
credential and access to the actual PDF deployment are still required for rollout.
