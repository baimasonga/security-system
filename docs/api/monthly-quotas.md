# Monthly Quota Accounting

Numeric entitlement keys ending in `_monthly`, such as `ocr_pages_monthly`, define per-license UTC calendar-month allowances. Limits resolve from the current subscription plan and license overrides. All organization members using that license share the allowance. Separate licenses have separate allowances. A zero allowance permits no consumption.

## Read Usage

```text
GET /v1/organizations/{orgId}/licenses/{licenseId}/usage
Authorization: Bearer <session-token>
```

The response contains `license_id`, `period`, `resets_at`, commercial `status`, and `items` with `entitlement`, `limit`, `used`, and `remaining`. Reads use one grouped ledger query for all allowances. Ineligible licenses retain their usage history and report `unavailable`; remaining allowance does not authorize execution. The portal displays usage in license details without a spending action.

## Consume Allowance

```text
POST /v1/organizations/{orgId}/licenses/{licenseId}/usage
Authorization: Bearer <session-token>
Content-Type: application/json
```

```json
{
  "entitlement": "ocr_pages_monthly",
  "units": 3,
  "idempotency_key": "unique-operation-id-001"
}
```

Only positive integer units are accepted. Use a fresh random operation ID (16–128 letters, digits, underscores or hyphens); repeat it only for the same operation and payload. The response is an accounting receipt with `id`, `license_id`, `entitlement`, `period`, `units`, and `created_at`. Only the operation ID digest is stored.

Matching retries return the original receipt without a second charge, including after month rollover. Changed units or entitlement under the same operation ID return `409`. Exhaustion returns `409`; missing allowances and ineligible licenses return `403`. Nonmembers, cross-tenant references and canary licenses return `404`. Unknown body fields are rejected. Usage and audit commit together under the license lock.

## Execution Boundary

A receipt is not a bearer capability, proof of payment or evidence that OCR/AI work ran. This release implements accounting and enforcement, not those processing services. A future processing handler must durably deduplicate execution using the same operation ID and authorize the actual work server-side. Replaying a receipt must never repeat external work. Keep external effects outside retryable database transactions.

## Migration and Verification

Apply migration `0008_monthly_quotas` with the schema owner, then run `npm run db:grants` and `npm run db:check` using the deployment instructions. The application role receives SELECT/INSERT only on `quota_charges`; it cannot rewrite or delete receipts. Historical receipts remain so old operation IDs cannot recharge after a monthly reset. There is no refund or offline quota grant in this release.

Behavioral and adapter tests cover concurrency, tenant boundaries, rollback, retry conflicts, rollover, downgrade, subscription plan changes, expiration and canary isolation. The load tool supports `--scenario quota-ramp --quota-limit 20 --rps 20 --seconds 4 --assert-clean` against a fresh test database. It pairs retries on one license and verifies exact usage, receipt count and audit integrity; quota refusals are expected outcomes.
