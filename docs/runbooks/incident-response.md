# Incident Response Runbook (V1)

Status: **drafted, not yet rehearsed** (Definition of Done requires a rehearsal
before any production launch — tracked in the handoff doc). Commands below refer
to code paths that exist and are tested; operator tooling/UI for them arrives
with the admin console.

Severity: **SEV1** forged/unauthorized leases, key compromise, cross-tenant leak ·
**SEV2** mass abuse, audit-chain break · **SEV3** single-customer issues.
First actions for any SEV1/SEV2: open an incident channel, assign a commander,
start a timeline, **preserve** the audit log and application logs (do not
restart or redeploy until snapshots are taken).

## A. License-signing key compromise

Indicators: leases verifying that the platform never issued (jti missing from `leases`), unexplained `key.*` audit events, key material exposure report.

1. Declare SEV1. Freeze deploys.
2. Generate/activate the **standby** key (`activate(newKid, reason)`), then `revoke(compromisedKid, reason)`. Signing continues under the new key; the revoked key leaves the trust bundle at once.
3. Confirm `GET /v1/keys/trust-bundle` no longer lists the old `kid`; run a refresh from a test device and verify the new `kid`.
4. Clients with an old pinned bundle: ship a client update containing the new public key (see key-management §3 limitation); until then forged leases signed by the old key remain accepted by those clients — this is why the signed bundle-update path (Milestone 3) is a launch prerequisite.
5. Query `leases` for anomalous jti/activation patterns; suspend or revoke affected licenses (`POST /v1/admin/organizations/{org}/licenses/{id}/revoke`, reason mandatory).
6. Post-incident: root-cause, rotate all secrets that shared the exposure path, update threat model + this runbook.

## B. Canary / honeypot license activated

Indicator: security signal `canary_license_activated` (severity high) and audit `security.canary_activated`.

1. The caller already received a generic `invalid license`; no access was granted.
2. Identify the account/session (`user_id` in the signal) and the pseudonymous installation. Review that account's recent audit trail.
3. Treat as a leaked-key-list scraper: consider suspending the account's licenses (reason: "canary activation, ticket #…") and blocking the network range at the edge.
4. Never reveal to the customer why the key was special.

## C. Suspected key sharing / piracy of one license

1. `GET /v1/admin/organizations/{org}/licenses/{id}/activations` — review device count and activation history (audit: `activation.created|reissued|rejected`, `security.device_key_conflict`).
2. Prefer graduated action: contact customer → reduce device limit via plan/override → `suspend` (reversible, reason mandatory) → `revoke` (terminal).
3. Remember: leases already issued remain valid offline until `exp` (R-1).

## D. Audit chain verification failure

Indicator: `GET /v1/admin/audit/verify` returns `ok: false`; signal `audit_chain_broken`.

1. SEV2. Do not "repair" rows. Snapshot the database.
2. Identify `broken_at_seq`; compare with backups/WAL to find the first divergence; determine whether it is corruption or tampering (database triggers reject UPDATE/DELETE, so tampering implies DB-superuser access → escalate to SEV1).
3. Restore the chain from a verified backup into a forensic copy; document the gap; resume appending only after the commander approves.
4. **Use the external witness** (ADR-010): fetch the witness's stored manifests from a separate machine and run `DATABASE_URL=… node tools/verify-anchor.ts witness.jsonl` against the suspect database and against the restored copy. The first manifest that no longer holds (`chain@seq`) dates the rewrite; every manifest before it vouches for the history older than that. Anchoring refuses to publish a log that fails verification, so a gap in witnessed anchors begins when tampering began.

### D2. Anchor publication failing (`audit_anchor_publish_total{outcome="failed"}`)

The witness is unreachable or rejecting. Nothing is wrong with the log, but the detection window is growing. Check `GET /v1/admin/audit/anchors` for the recorded `error` (`witness unreachable|timed out|responded <status>`), the URL/token configuration and the witness's own health; after fixing, `POST /v1/admin/audit/anchors` (reason required) publishes immediately.

## E. Cross-tenant exposure suspected

1. SEV1. Disable the affected route at the edge (WAF rule) if identifiable.
2. Reproduce with the `tests/security` tenant-isolation suite pattern against production-like data; add the failing case as a regression test first.
3. Notify per legal obligations after scope is known; rotate sessions (`revoke` all) if token exposure is possible.

## F. Operator account compromise

1. Contain first: `POST /v1/admin/freezes {scope: "platform", reason}` (ADR-022) — immediate, one operator. It stops
   new operator grants, catalog changes, license issuing/reinstating, subscription changes, member additions and trials
   everywhere; device flows, reads, suspension and revocation keep working. Use `scope: "organization"` when only one
   tenant is affected.
2. Remove the operator: `operator.revoke` privileged request + approval by a second operator, or out of band with
   `revokePlatformAdmin(email, reason)` from the deployment — effective on the **next request** (role is re-checked
   per request).
3. Review `admin.access_denied`, `privileged.*` and all `actor.type=operator` audit events for the account's window;
   reverse malicious changes with new audited operator actions.
4. Lift the freeze with a `platform.unfreeze` (or `org.unfreeze`) request approved by a second operator.
