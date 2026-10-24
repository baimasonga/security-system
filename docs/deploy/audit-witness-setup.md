# Production audit witness: recommended setup

Status: prepared deployment specification, **not provisioned or active**. There is
no external witness configured in the inspected deployment, and no successful
published anchor was found on 24 October 2026. The application's existing
HTTPS anchor publisher, operator actions and offline verifier implement ADR-010.
Do not hide the startup warning or substitute a local file for independent evidence.

## Recommended trust boundary

Use a separate AWS account for an S3 Object Lock bucket and a small HTTPS witness
receiver (API Gateway and Lambda). Keep account recovery, retention administration
and evidence-reading credentials separate from Railway and Supabase. Railway gets
only an append-only receiver token. The receiver must have no credentials for the
Warrior database. Cloudflare remains the application deployment alternative; its
ordinary mutable storage is not automatically an immutable audit witness.

This is a deployment specification for a production receiver, not an assertion
that the development `tools/anchor-witness.ts` is safe for production. The receiver
must be implemented and accepted against the contract below before activation.

## Resources and controls to provision

1. Select the independent AWS account and region. Protect its administrator with
   MFA and a separate recovery path. Review costs before provisioning.
2. Create a new S3 bucket with versioning, Object Lock enabled, public access
   blocked, default encryption and a policy denying non-TLS requests. Configure
   default **COMPLIANCE** retention; **365 days is the proposed starting policy**,
   subject to the owner's retention requirements. It cannot be shortened or
   bypassed for retained versions, including by root. Confirm the retention period
   before deploying; this document does not authorize an irreversible retention
   commitment. Retention, not bucket naming, provides protection against rewrites.
3. Deploy the receiver on an HTTPS endpoint accepting only `POST /anchors`, with
   bounded requests (at most 8 MB), authentication, rate limits, body timeout and
   fixed secret-free error responses. No redirect, arbitrary destination, database
   access, general object download, object deletion or retention editing endpoint.
4. Generate a separate random bearer token in a password manager or Secrets
   Manager; install it privately in the receiver and Warrior. Never place it in
   source, command arguments, logs, screenshots or chat. Do not reuse MFA,
   database, signing or email-provider secrets.
5. Restrict receiver IAM to `s3:PutObject` on the designated evidence prefix and
   only the read permission required to implement exact idempotent receipts.
   Grant no delete, policy, lifecycle, Object Lock, retention-reduction or bucket
   administration permissions. Keep evidence readers independently controlled.
   Retained evidence contains chain identifiers/tails; it is private operational
   metadata and must not be publicly readable.
6. Disable request-body and authorization-header logging. Receiver operational
   logs may contain only fixed outcomes, counts and a generated reference. Use
   independent monitoring for receiver failures and evidence-retention expiry.

## Receiver contract and acceptance

Use the exact version-1 manifest and digest rules from `packages/audit/src/index.ts`
(`AnchorManifest`, `computeAnchor`, `manifestProblem`), not a newly invented
canonicalization. Validate version, field types, safe integer sequence numbers,
unique chain identifiers and the digest. Reject malformed or oversized input.
Authentication must be checked before accepting evidence. Neither a valid token
nor an internally consistent manifest proves the database's statements are true;
retaining every earlier accepted manifest is what detects later rewrites.

Persist the full manifest as a locked object version before acknowledging. A
repeat of the same manifest must return the same durable receipt or a reference
to an already retained copy. Preserve version-specific retrieval: a newer object
at the same key must not hide or replace the earlier retained evidence. An object
key alone is not a receipt unless immutable/versioned retrieval is guaranteed.
Return an HTTP 2xx only after durable storage and retention succeed, with a stable
printable `X-Witness-Receipt` header (1–256 ASCII characters). Fail closed on
storage/retention errors; never acknowledge a write merely held in memory.

Before connecting production, use synthetic manifests to verify:

- invalid token, malformed/duplicate-chain/digest mismatch, excessive body and
  timeout refusal; fixed responses must not expose secrets or payloads;
- persistence and stable receipts across retries and receiver restart;
- earlier versions remain retrievable after a later manifest or same-key write;
- delete/overwrite-of-retained-version and retention-reduction attempts are denied
  even with the receiver credentials; deny access from Warrior database credentials;
- an intentionally altered synthetic audit history is rejected by the existing
  `checkAnchor` / `tools/verify-anchor.ts` against independently retrieved evidence.

Do not corrupt production audit history to perform acceptance.

## Warrior activation after receiver acceptance

Stage these variables on **Warrior**, preserving all other working settings:

| Variable                        | Value                                           |
| ------------------------------- | ----------------------------------------------- |
| `AUDIT_ANCHOR_URL`              | Accepted receiver's HTTPS `/anchors` endpoint   |
| `AUDIT_ANCHOR_TOKEN`            | Privately installed dedicated bearer token      |
| `AUDIT_ANCHOR_INTERVAL_SECONDS` | `300` initially; tune for audit volume and cost |
| `AUDIT_ANCHOR_DISABLED`         | Remove it or set `false`                        |

Use the operator-only `POST /v1/admin/audit/anchors` action with a reason, or wait
for the initial publication (about five seconds after startup). Inspect
`GET /v1/admin/audit/anchors` for a successful publication and receipt. A configured
URL or absent warning alone is not acceptance. Retrieve the retained manifest
independently using the witness's read-only operator path, then run the existing
offline checker with verified TLS and the restricted database connection (loaded
privately into the process environment). Never paste a database URL into chat.

Keep the publisher enabled and monitor fresh successful receipts. Alert if the
witness is unreachable or the latest successful publication becomes stale. During
an outage user operations continue; recent unwitnessed history remains exposed.
Retain the bucket and all evidence on rollback. Disabling anchoring explicitly
reaccepts R-13; it must never delete the witness or be presented as a fix.

## Incident email is a separate activation

The provider and fenced delivery implementation now exist; see
[operations automation](operations-automation.md#incident-email-optional). Install
provider secrets privately, enable `OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED`, and
verify the rule creator's email through Account. The inspected owner address was
not yet verified; do not mark it verified directly in SQL. No real notification
has been sent as part of this repair. After the owner authorizes an inbox test,
use isolated synthetic inventory to confirm one opened and one recovery email.
Provider acceptance alone is not proof of inbox delivery. Never stop production
scanner/converter services to exercise notifications.
