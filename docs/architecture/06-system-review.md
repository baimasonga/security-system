# System behavior and review

The system is a backend trust and licensing API. Railway runs the Node/Fastify service; Supabase provides PostgreSQL. The root URL serves the same-origin customer portal, operator console and device demo (ADR-015). `/healthz` confirms the HTTP process responds, not ongoing database connectivity.

## Request and trust flow

1. Users register and log in. Passwords use scrypt; only session-token hashes are persisted. Expired, revoked, or disabled-user sessions fail authentication. Organization membership and permissions authorize customer operations; platform operators manage catalog and license state.
2. Operators define products and plans, then issue subscriptions and licenses. License keys are returned once and persisted as HMACs. Current subscription plans determine new lease entitlements; clients cannot choose plan state.
3. Activation requires a logged-in organization member, a license key, and possession of the device private key through a single-use challenge. Transactions lock the license while enforcing device slots and writing the activation and audit record atomically.
4. Refresh issues a signed, expiring lease bound to the device and installation. The SDK verifies its signature and claims offline and applies validity/grace policy. Revocation and plan changes affect future server decisions; already-issued offline leases retain their expiry.
5. Audit events form hash chains. Mutations write audit records in the same transaction as state. An independent witness can anchor chain heads to detect later rewriting by a database owner.

## Deployment and operational boundaries

Owner credentials are for migrations and grants. The API uses `trust_app` in the private `trust` schema, verified TLS, stable signing key and pepper, production persistence, and a deliberate audit-witness policy. Runtime starts only after configuration, role, and migration checks pass.

HTTP limits use PostgreSQL counters with local fallback; login lockout is persistent. Background tasks purge expired state and publish audit anchors. Database outages may leave `/healthz` returning OK while business requests fail; monitor request errors and fallback metrics alongside deployment health.

## Review results

Confirmed and corrected defects include stale activation validation restoring inactive state, subscription changes leaving new leases on old plans, oversized entitlement snapshots creating unverifiable leases, TLS downgrade URL flags, a localhost URL concealing a remote `host` override, and rate counters resetting during fallback. Tests cover these regressions and both PostgreSQL owner and app-role adapters.

This review does not establish that every possible defect is absent. Production credentials, Railway settings and deployed revision require live verification; local validation does not deploy repository changes. No frontend or automated billing integration is provided by these API flows.
