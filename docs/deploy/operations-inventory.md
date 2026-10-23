# Operations inventory rollout (OPS-002)

> Historical rollout details. Use [current operator onboarding](operator-onboarding.md) for the current process and implementation/activation matrix.

This guide covers inventory. Credential management has a
[separate rollout guide](operations-credentials.md); ingestion, probes, alerts and a
fleet dashboard remain later tasks. No infrastructure or commercial access changes
are performed by registering an application.

## Local and staging enablement

1. Back up the target database and run owner migrations with `npm run migrate`.
   Migration `0017_operations_inventory` adds four tables and immutable identity /
   version guards. Re-run `npm run db:grants` with the deployment owner. The app
   role receives SELECT/INSERT/UPDATE only; it cannot delete inventory tombstones.
2. Set `OPERATIONS_INVENTORY_ENABLED=true` on a **test** deployment. It defaults
   to false; any other value than `true`/`false` is a startup error. Disabled
   inventory routes return 404 after session authentication. No secrets are needed.
3. Sign in as an admin/owner of the test organization. Use the account session
   bearer, never a license key. `ops:read` and `ops:manage_inventory` are granted
   only to those two roles; platform operator status grants no tenant bypass.
4. Register an application, then its environments, then components. The implemented
   HTTP schemas are in [live OpenAPI](../api/openapi.yaml). All writes need a
   reviewed reason code; PATCH and DELETE additionally need `expected_version`.
   Codes are immutable, content-free slugs. DELETE archives; codes cannot be reused.
5. Verify reads, ordinary-member refusal, wrong-organization 404, stale-version
   409, freeze refusal, atomic audit and tombstone behavior. Check existing license
   activation remains unchanged. Credential management additionally requires its separate flag and fresh MFA;
   follow its rollout guide. Event ingestion is not implemented yet.

Example create body (replace the user ID with an active member of the same org):

```json
{
  "code": "rokela-pdf",
  "owner_user_id": "usr_aaaaaaaaaaaaaaaaaaaaaaaa",
  "criticality": "high",
  "product_id": null,
  "reason": "initial_setup"
}
```

POST to `/v1/organizations/{orgId}/operations/applications`. The returned opaque
application ID is used in nested environment/component routes. Product linkage is
optional and must reference an active catalog Product; it never grants a license.
No URL, customer/file name, recipient address or free-form description belongs in
inventory. Dependencies are same-organization component IDs, never probe targets.
Lists order by ID, exclude archived rows and accept scoped last-ID cursors; direct
reads preserve archived records. Caps include archived rows: 100 apps/org, 20
environments/app and 100 components/environment. Pagination has a maximum of 100.

## Locking and failure behavior

PostgreSQL serializes inventory writes on an `operations_accounts` row per
organization. This is the organization lock anchor and subsumes ancestor/graph
locks for this inventory-only slice. Scope/RBAC/freeze/owner/Product validation
inside the transaction uses that transaction's connection; it must never acquire
another pool connection while holding the organization lock. This avoids pool
exhaustion with many requests waiting on the same row. Future credential/event
work must acquire this anchor first and preserve the documented lock order.

Changes and audit append commit together. A failed DB/audit write returns a fixed
503 and no success acknowledgement. Retry an ambiguous create by listing the
immutable code first; use the current version before retrying a PATCH. An ambiguous
commit does not permit blindly replaying a mutation with a different identity.
Errors never expose validation inputs, unknown field names or SQL details.

Organization membership removal is currently not implemented by AuthService. The
composite owner membership FK prevents future removal without an explicit owner
transfer first. Future removal/deactivation workflows must preserve this invariant
and account for already-disabled users; inventory creation/owner changes require
an active same-organization user.

## Verification and rollback

- `npm run check` and `npm run test:db` cover the existing product plus inventory.
- `DATABASE_URL=<disposable local database> node tools/loadtest/operations.ts`
  runs real HTTP and PostgreSQL with fsync on in a temporary schema. It asserts
  exact cap/conflict/atomic-audit results and cleans up its schema. This is an
  integrity/contention test, not a production throughput claim.
- Before production, review staging evidence and deploy the migration before the
  application release. No production rollout has been performed by local tests.
- If credential management was enabled later, disable its flag before disabling inventory.
  Roll back inventory by setting `OPERATIONS_INVENTORY_ENABLED=false` and deploying the
  preceding app version. Keep inventory tables and audit evidence for inspection;
  do not drop data or roll back licensing to disable monitoring.
