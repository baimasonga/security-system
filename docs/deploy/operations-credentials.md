# Operations integration credentials (OPS-003)

> Historical rollout details. Use [current operator onboarding](operator-onboarding.md) for the current process and implementation/activation matrix.

Credential management is implemented; event ingestion remains OPS-004. A credential
has no account, inventory-read, licensing, incident or infrastructure authority.
No live application is connected by this release.

## Staged enablement

1. Deploy OPS-002 inventory first. Run owner migrations through
   `0018_operations_credentials`, then `npm run db:grants`. The new table receives
   SELECT/INSERT/UPDATE only. Composite ancestry FKs and lifecycle guards preserve
   identity, scope, purpose, source, digest and irreversible revocation/rotation.
2. Reuse the existing `MFA_ENCRYPTION_KEY`; do not replace it to enable this feature.
   Set both `OPERATIONS_INVENTORY_ENABLED=true` and
   `OPERATIONS_CREDENTIALS_ENABLED=true` in a test deployment. Both default off;
   credential enablement requires inventory and the MFA encryption key at startup.
3. Register active application/environment inventory. Sign in as an active admin
   or owner of that organization and enroll authenticator MFA. Operators require
   the same membership; there is no cross-tenant operator bypass.
4. Use the four credential management operations in [live OpenAPI](../api/openapi.yaml).
   The base path is
   `/v1/organizations/{orgId}/operations/applications/{applicationId}/environments/{environmentId}/credentials`.
   List uses GET; issue POSTs to the base path; rotate/revoke POST to
   `/{credentialId}/rotate` and `/{credentialId}/revoke` respectively.
5. Every mutation needs a reviewed reason and a **fresh six-digit authenticator
   code**. A recovery code, remembered MFA flag or old session factor does not
   qualify. Step-up consumes the code in AuthService's transaction before the
   operations transaction. A conflict, failed audit/commit or lost response does
   not restore the code. Retry with a fresh authenticator time step.

Issue body:

```json
{
  "purpose": "events:write",
  "ttl_seconds": 86400,
  "reason": "initial_setup",
  "mfa_code": "123456"
}
```

The MFA value above is illustrative, not an enrolled factor. Credentials are
`ops_v1.<public-id>.<secret>`, with a 128-bit public ID and independent 256-bit
CSPRNG secret. Issue/rotation return the token once with `Cache-Control: no-store`.
Lists contain metadata only; no route retrieves an old secret or its digest.
Store the token in the monitored application's server-side secret manager. Never
place it in browser code, telemetry, support screenshots or logs. Do not issue a
production token until its receiving integration is ready.

## Rotation, revocation and failure

TTL is 1–90 days. At most two unrevoked/unexpired credentials exist per environment
and purpose. The only purpose/source are `events:write` / `backend_report`.

Rotation accepts `ttl_seconds`, `overlap_seconds` (0–3600), `reason`, `mfa_code`.
The predecessor expires at the earlier of its existing expiry or now + overlap;
zero overlap revokes it immediately. A successor can rotate again only after its
active overlap predecessor expires or is revoked. A predecessor cannot itself
be rotated twice. With two independent credentials and no active overlap,
zero-overlap replacement is allowed atomically: active count stays two. A
nonzero overlap needs an available slot. Revoking an overlap successor does not
permit repeatedly rotating its still-active predecessor.

Revocation is idempotent and audits its first transition only, while every retry
still requires fresh MFA. It remains available during a platform/org freeze and
when parents are disabled/archived. Reads preserve metadata history. New issuance
and rotation require active parents and an unfrozen scope. Disabling parents
suspends valid credentials; reactivation cannot resurrect a revoked/expired one.

If an issue response is lost, list public IDs and rotate/revoke with fresh MFA.
Do not replay issuance expecting the old token. Failures return fixed problems
with no request values, MFA code, unknown field names or SQL details. Credential
routes suppress automatic raw-URL logging; safe route metrics and audit remain.

## Verification boundary for OPS-004

Backend verification uses `CredentialService.withCredential(token, expected,
callback)`. It derives identity from the stored credential, compares fixed-size
SHA-256 digests with `timingSafeEqual` (dummy digest for an unknown ID), acquires
the organization's `operations_accounts` anchor, and rechecks current credential
and ancestor state inside the transaction. Expiry/rollout are checked again after
the callback before committing. Frozen scopes may still report observations.

The callback receives trusted scope/provenance and the **same transaction** for
future event writes. It must be retry-safe and perform no network or other
irreversible effects. Do not cache its returned identity as authorization for a
later commit. Revocation waits for a guarded transaction; whichever obtains the
shared lock first wins. This tests the transaction primitive, not an implemented
event collector. OPS-004 still needs strict event schemas, component ancestry,
quotas, durable receipt semantics, deduplication and retention.

Authority and live-session checks inside management transactions use the same
connection, avoiding the pool exhaustion found in OPS-002. MFA deliberately runs
before that lock; no second pool connection is acquired by a locked callback.

## Verification and rollback

- `npm run check` and `npm run test:db` include credential service, HTTP and both
  memory/PostgreSQL store contracts, including the least-privilege application role.
- `DATABASE_URL=<disposable local database> node tools/loadtest/operations-credentials.ts`
  requires fsync on and creates/drops an isolated schema. Three separate MFA-enabled
  admins contend using a two-connection pool. It checks exact issuance/rotation
  counts, overlap refusal, guarded commit/revoke ordering, absence of plaintext
  and the audit chain. It is integrity evidence, not sustained capacity evidence.
- The existing inventory contention scenario is rerun to check the shared lock /
  adapter changes; compare its exact state/audit counts, not unlike workloads' RPS.
- Roll back by disabling `OPERATIONS_CREDENTIALS_ENABLED`. The verifier refuses
  credentials while disabled. Keep tables, digests and audit evidence; do not drop
  history or modify customer licenses. Unrevoked, unexpired tokens can work again
  after re-enable, so revoke deliberately before permanent integration retirement.
- No real recipients, production keys, production migrations, alerts, external
  probes or live application integrations are configured by local tests.
