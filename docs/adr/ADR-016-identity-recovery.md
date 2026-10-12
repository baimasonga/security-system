# ADR-016 — Email verification and single-use password recovery

Status: Accepted. Trust boundary: email possession authorizes account verification/password replacement.

## Decision

Recovery/verification tokens contain 256 bits of randomness and are stored only as SHA-256 digests. A user has at most one row per purpose; replacement invalidates earlier links. Links expire at 15 minutes, and consumption is conditional on user, purpose, digest, expiry and unused state. Concurrent consumers cannot both succeed. Recipient requests are throttled per IP and per user/purpose (one delivery per minute). Public reset responses have the same status/body for existing and nonexistent accounts; they do not wait on delivery-network latency. Timing under database stress is not promised indistinguishable.

Consumption locks the user before the token. Password hashing happens outside the retryable transaction. Token consumption, password update, session revocation, lockout clearing and audit write commit atomically. Login rechecks the verified password hash under the same user lock before creating a session, so an old password verified before a concurrent reset cannot create a surviving session afterward. Email verification consumes a distinct-purpose token and writes email_verified_at atomically with audit. Verification is recorded but not yet a mandatory gate for existing V1 accounts.

Links use root URL fragments (`/#reset=…` and `/#verify=…`). The browser removes fragments from history before processing. Tokens/passwords are never echoed in API errors, audit metadata or logs. The account API reveals email/verification status only to its own authenticated user.

## Delivery and configuration

`RESEND_API_KEY`, `EMAIL_FROM` and `PUBLIC_ORIGIN` enable recovery. The sender must be verified with Resend. PUBLIC_ORIGIN is validated, must contain no credentials/path/query/fragment, and must use HTTPS in production. Destination URLs are not constructed from request Host headers. Without delivery configuration, recovery is disabled consistently and the browser omits the forgot-password action.

Email sending occurs after the token/audit transaction, outside retries; message-digest idempotency keys prevent provider duplicate delivery. Failed delivery records a content-free audit event, not a provider error body. Shutdown waits for in-flight delivery. **There is not yet a durable encrypted mail outbox:** process failure after commit can lose a send; users may request a new link after the cooldown. Do not claim guaranteed delivery or resend semantics. The local MemoryMailDelivery adapter is a test seam and has no production HTTP outbox route.

## Migration and verification

Migration 0006 adds users.email_verified_at and identity_tokens. Application grants explicitly cover the new table. Apply migrations and grants before deploying the new API. Contract tests exercise token binding/expiry/one-use across memory and PostgreSQL. HTTP tests cover generic requests, cooldown, expiry, replay, wrong purpose, concurrent consumption, verification and session revocation. Login races and the recovery control are mutation-checked. Browser flows exercise the delivered fragment links with a local captured-mail adapter. MFA, passkeys and federated-account linking remain separate work.
