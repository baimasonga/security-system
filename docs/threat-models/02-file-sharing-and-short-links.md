# Threat Model — File sharing, documents, short links and upload requests (ADR-021)

Method: STRIDE over the boundaries in [architecture/10 §2](../architecture/10-file-sharing-and-short-links.md#2-components-and-trust-boundaries).
Test shorthand: **SH** = `services/platform-api/test/sharing.test.ts` (acceptance), **SS** =
`services/platform-api/test/sharing-security.test.ts`, **SC** = `sharing-config.test.ts`, **POL** =
`packages/sharing/test/policy.test.ts`, **TOK** = `tokens.test.ts`, **SCAN** = `scan.test.ts`, **CON** =
`store-contract.ts` (memory + PostgreSQL), **S3** = `object-store-s3.test.ts`, **AV** = `clamd.test.ts`. SH/SS also run on
PostgreSQL as superuser and as the least-privilege application role.

## Assets

Shared document and file contents; confidential file names; link tokens, passwords and grants; recipient identities
and receipts; organization quotas (cost); the platform's reputation (phishing/malware hosting); object-storage
credentials.

## Threats and mitigations

| ID  | Threat                                                   | Mitigation                                                                                                                                                                                                       | Evidence                                                                 |
| --- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| S-1 | Guessing or enumerating share/request/confidential links | 256-bit (share, request) and 96-bit (confidential short) derived tokens; only SHA-256 hashes stored; unknown and malformed tokens → 404; rate limits per IP                                                      | TOK; SS "rejects malformed…"                                             |
| S-2 | Short URL treated as authorization                       | Confidential short links only redirect; the share link's status, password, expiry and recipients still apply; no aliases/passwords on confidential links                                                         | SS "separates public and confidential"                                   |
| S-3 | Password brute force                                     | scrypt hashes; 10 failures → 15-minute per-link lock; per-IP route limits; failures recorded as receipts                                                                                                         | SS "locks out password guessing"                                         |
| S-4 | Recipient impersonation via unverified email             | Named recipients require a signed-in account with a **verified** email; grants bound to the user; restriction re-checked every request                                                                           | SS "enforces recipient restrictions" (mutation-checked)                  |
| S-5 | Forged or replayed grant                                 | HMAC grants with purpose-derived key, 15-minute expiry, bound to link and user; each use re-evaluates link and target                                                                                            | TOK; SS forged grant; SH grant after expiry                              |
| T-1 | Cross-tenant access/modification                         | Org membership authorization; every query scoped by `org_id`; composite FKs; 404 for foreign ids                                                                                                                 | SS "returns 404 for every cross-organization reference"; CON tenant test |
| T-2 | Unpublished edits exposed                                | Drafts are never link targets; `latest` follows only explicit publish; approval gate                                                                                                                             | SH "1 & 5"; SS review                                                    |
| T-3 | Revocation not taking effect                             | Status re-checked per request and under the link row lock; signed URLs live ≤ 60 s; documented limit: downloaded copies cannot be recalled                                                                       | SH "3 & 4" (mutation-checked)                                            |
| T-4 | Download limit bypass by concurrency                     | Count incremented under the account + link locks                                                                                                                                                                 | SS concurrency (6 parallel → exactly 2)                                  |
| T-5 | Tampered signed upload/download URL                      | HMAC/SigV4 signatures cover key, part, size, expiry, type, disposition; exact content-length                                                                                                                     | SS content origin; S3 vector                                             |
| I-1 | Malware or disguised executables distributed             | Type allowlist (no html/svg/js/exe), magic-byte check, EICAR, ClamAV in production (fail closed), quarantine until clean                                                                                         | SS quarantine; SCAN; AV; SC                                              |
| I-2 | Stored XSS via shared content                            | Content served only from a separate origin; `nosniff`, fixed type, `Content-Disposition`, CSP `default-src 'none'` + `sandbox` (PDFs excepted for the viewer); portal CSP never allows that origin to run script | SS content origin + page CSP                                             |
| I-3 | Confidential names in analytics/logs/audit               | Events store ids, bot flag and referrer host only; audit metadata has ids/hosts, not titles or file names; request logs use route templates                                                                      | SH "7"; SS quarantine (audit has no file names)                          |
| I-4 | SSRF via destinations, previews or domain checks         | Destinations validated, never fetched; no link previews; domain verification uses DNS TXT only; storage requests only to the configured endpoint                                                                 | POL; SS destinations                                                     |
| I-5 | Upload-request submitters seeing others' files           | Submission secret (hash stored); APIs return only the caller's submission                                                                                                                                        | SH "6"                                                                   |
| D-1 | Storage/bandwidth/cost exhaustion                        | Separate meters and plan limits checked under the account lock before uploads; abandoned uploads expire; file size limits                                                                                        | SS quotas (parallel reservations)                                        |
| D-2 | Lockout used to deny a recipient                         | Accepted trade-off (per-link lockout is short); owner can rotate the password or issue a new link                                                                                                                | — (documented)                                                           |
| E-1 | Owner bypasses an abuse suspension                       | Operator hold cannot be lifted by owners; resolution needs operator role + reason; audited                                                                                                                       | SS abuse (mutation-checked)                                              |
| E-2 | Member manages others' links                             | Creator or `share:manage` (admin/owner) required                                                                                                                                                                 | SS roles                                                                 |
| R-1 | Denying a destination change or revocation               | Audit events in the same transaction; append-only destination history                                                                                                                                            | SS history                                                               |
| R-2 | Receipts overstated                                      | Visits never presented as reading; bots separated; unverified names labelled                                                                                                                                     | SH "7"                                                                   |

## Residual risks and open items

- PDFs are served inline without CSP sandbox (browser viewer requirement); content origin isolation is the control.
- Without ClamAV (development, or explicit production risk acceptance) only structural checks run.
- The S3 adapter has not been exercised against a live bucket; R2 bucket CORS must restrict PUT/GET origins to the
  portal origin.
- Custom-domain TLS and routing are edge configuration; a verified domain whose DNS later moves keeps resolving in
  our namespace until the owner removes it.
- Per-organization serialization of sharing writes (account lock) has not been load tested.
