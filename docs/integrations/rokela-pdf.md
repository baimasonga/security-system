# Rokela PDF — second application integration brief

Status: **planned, not connected by this document**. Depends on OPS-004/006; tracked
as OPS-007 in [the program](../programs/operations-security.md).

## Inventory and scope

Application code suggestion: `rokela-pdf` (finalize in OPS-001). Register production
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

These names are proposals for reviewed schemas, not accepted existing telemetry types.

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

The envelope needs version, scoped event ID, component, occurrence time and outcome.
Warrior assigns receipt time and trusted source identity. Derive severity under
server-owned rules. Decide safe request/job correlation IDs in OPS-001; arbitrary
URLs, headers, bodies, stack traces and email addresses are not permitted metadata.

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
