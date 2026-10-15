# ADR-021: File sharing, document publication and short links

Status: accepted (phase 1 and 2 implemented; phase 3 partially, see [architecture/10](../architecture/10-file-sharing-and-short-links.md#7-phased-build-plan)).

## Context

Rokela PDF Pro Web users need to share finished documents and other permitted files, collect files from others,
and manage short links from the same workspace, reusing the platform's identity, organizations/RBAC, audit, quota
and background-job patterns. File content is untrusted; links travel through email, chat and print, so a URL must
never be the only thing standing between a stranger and a confidential document.

## Decision

1. **New bounded context `@trust/sharing`** (allowed imports: audit, crypto, shared-types). It owns transfers,
   documents/versions, share links, short links, upload requests, receipts, aggregates, jobs, custom domains,
   branding, abuse reports and usage. Identity, membership, plan entitlements and password hashing are injected by
   the composition root, so sharing cannot bypass the auth or licensing services.
2. **Bytes never pass through the API.** The API authorizes, then hands out short-lived signed URLs for private
   object storage on a separate origin: multipart part PUTs (exact signed size, 15 min) and GETs (60 s, fixed
   `Content-Type` and `Content-Disposition`). Adapters: S3-compatible (Cloudflare R2/S3/MinIO, SigV4 on
   `node:crypto`) for production; a local signed-URL store with its own listener (the "content origin") for
   development and tests. Production refuses local storage.
3. **Quarantine before availability.** Completion moves an object to `quarantined`; a fenced background job checks
   it (format magic bytes, EICAR signature, size/digest, then ClamAV via clamd INSTREAM when configured; production
   requires ClamAV unless `SHARING_MALWARE_SCAN_DISABLED=true` records the accepted risk). Only `clean` objects can be
   signed for download. Repeated scan failure rejects the file (fail closed).
4. **Explicit publication.** A document has one private draft (replaced by each editor save) and immutable exported
   versions (each referencing an immutable object; exports do not copy bytes). `latest` links serve only
   `published_version_id`, which changes only through the publish endpoint; `fixed` links pin one version. With
   `require_approval`, publication (and view/download sharing of unpublished versions) needs an approval from a
   reviewer other than the author and no open change request.
5. **Share links are access policies.** 256-bit tokens derived as `HMAC(key, purpose:id:salt)`; the database holds
   only `SHA-256(token)` and the salt, so owners can re-display links while a database leak alone does not reveal
   them. Policies: view/download/review, password (scrypt, per-link lockout 10 failures → 15 min, plus per-IP rate
   limits), expiry, exact download limits (counted under the link row lock), members-only or named recipients
   (signed-in account with a **verified** email), notifications. Every public request re-evaluates status, expiry,
   target availability and restriction; short-lived grants (15 min) carry no authority of their own. Revocation
   therefore applies to the next request; already-issued download URLs expire within 60 s.
6. **Short links are pointers, not access control.** Public (marketing) links: readable alias or generated code,
   external `http(s)` destinations validated syntactically (no credentials, IP literals, internal names, odd ports,
   our own hosts or blocked hosts) and never fetched by the platform. Confidential links: 16-character derived codes
   (96 bits, hash-only storage) that redirect to a share link or upload request whose own policy applies; no aliases,
   passwords or custom domains. Destination edits keep a history row and an audit event.
7. **Upload requests** create submissions identified by a random submission secret held by the uploader (hash
   stored). The public API returns only the caller's own files; requirement types, counts, per-file/per-submission
   sizes and the organization storage quota are enforced before upload.
8. **Receipts and analytics.** Distinct `visit`, `access` (identified), `view`, `download`, `acknowledge`, review and
   password-failure events with ids, a bot flag and (for opens) the referring host only. No IPs, file names or
   titles. Short links keep daily aggregates only. Raw events: `SHARING_EVENT_RETENTION_DAYS` (default 180);
   aggregates 400 days.
9. **Commercial controls.** Limits resolve from the organization's currently valid licenses
   (`share_*` entitlements; most generous wins, free baseline below, hard ceilings above) and are metered separately:
   storage (live + reserved bytes), bandwidth (bytes of each issued download), processing (bytes scanned), uploads,
   API mutations. Checks happen under the organization's account row lock before uploads start and before exports.
10. **Retention and cleanup** run in the existing maintenance pass and the job worker: temporary transfers are purged
    at expiry, deleted items and expired upload requests next; abandoned uploads after 24 h. Object deletion is a
    retryable job that never deletes an object still referenced by a live draft, version, transfer file or submission
    file, and re-queues itself rather than forgetting an object.
11. **Abuse.** Public reports (same response whether or not the reference resolves); operators resolve with a mandatory
    reason, placing an **operator hold** the owner cannot lift; all audited.

## Locking and transactions

Lock order: `share_accounts` (organization) → document/transfer → link/short link → blob → job. Every sharing
mutation takes the account lock first (this serializes one organization's sharing writes; acceptable for the expected
rate and revisited if load tests show contention). Transaction callbacks derive state from reads and have no external
effects: multipart creation happens before the transaction (aborted on failure), object deletion and scanning happen
between two fenced transactions, and notification email is a queued job.

## Consequences

- New tables (migration 0011) and grants; the application role cannot delete versions, destination history or
  comments, and deletes only disposable rows (jobs, counters, retained events).
- New public routes; the OpenAPI drift test enumerates them. Pages use the strict portal CSP with `connect-src`
  extended to the content origin only.
- Watermarking, low-bandwidth previews and submission bundles need server-side PDF processing and are deferred
  (architecture/10 §6). Custom-domain TLS termination is an edge/operator step; the platform verifies ownership by
  DNS TXT and routes verified hosts to their own namespace.
- The S3 adapter is verified against the AWS SigV4 example and a protocol fake, not yet a live bucket.
