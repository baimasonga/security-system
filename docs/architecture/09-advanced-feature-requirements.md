# Advanced feature requirements — proposed defaults

The original brief is absent and the user has no further acceptance criteria. These defaults define conservative behaviors for subsequent implementation; they are not claims that the features exist.

## Identity

Verification and reset links are single-use, expire, are stored only as hashes, and do not reveal whether an email is registered. Password reset revokes all existing sessions atomically. TOTP enrolls only after password reauthentication and first-code verification; recovery codes are hashed and consumed once. Operators require MFA before privileged actions. Passkeys use WebAuthn with challenge expiry, origin/RP binding and verified signature counters; no custom protocol. Supabase federated identities map explicitly to local accounts and organization memberships; matching an email alone cannot link accounts.

## Billing, capabilities, usage and seats

Provider events require verified signatures, replay/idempotency protection and explicit subscription mapping. Client-submitted price/plan state never grants access. Capability tokens are short-lived, audience/device/license-bound and grant only resolved entitlements. Quota consumption is atomic, tenant-scoped and idempotent, with explicit billing-period boundaries and no negative/over-limit consumption. Seat assignments are unique and require organization administration; device slots and human seats are different resources. Offline transfer requires online revocation/confirmation with bounded existing-lease validity; it cannot promise instantaneous offline revocation.

## Device trust and policy

A device passport combines key identity with verified attestation results where supported. No browser user agent or self-reported flag counts as hardware evidence. Signals have provenance, timestamps and retention bounds. Deterministic policy rules return ALLOW/OBSERVE/STEP_UP_AUTH/RESTRICT/SUSPEND/DENY with reasons; hard signature, tenant and revocation invariants cannot be overridden by a score. Clone suspicion triggers observation or step-up first, not data deletion. Missing evidence is labeled unknown.

## Signed updates and supply chain

Release manifests include product, channel, version, hash/size and minimum supported version. An independent update-signing purpose is pinned to a trusted root, supports explicit rotation and expiry, and rejects rollback. Artifacts are immutable content-addressed objects; downloads verify integrity. SBOM and provenance are attached to each release and linked by digest. Production signing uses an explicitly selected KMS/HSM; local software keys are development adapters only.

## Privacy and workspace

The privacy firewall validates allow-listed telemetry schemas and rejects document content, personal identifiers and secrets. A security center explains permissions, device state and collected signal categories. Temporary workspace objects are tenant-isolated and encrypted with explicit limits, expiry and verified deletion; users retain export access when licensing expires. Object-storage credentials never reach the browser. Restore/retention policies require operational drills, not a passing unit test.

## Privileged operations

JIT grants expire and bind to a requester, exact operation/resource and mandatory reason. Sensitive changes require approval from a distinct MFA-authenticated operator; self-approval and replay fail. Freeze stops defined writes while preserving read/export/recovery access. Freeze/unfreeze, approval and execution are audited atomically. Break-glass access is bounded and produces an independent witness record.

## Proposed providers and external setup

The business is registered in Sierra Leone. Evaluate Paddle (merchant of record for software) first, subject to seller approval and supported payout arrangements. Do not assume direct Stripe onboarding is available. Current provider eligibility could not be fetched because those domains are blocked here, so confirmation is required before committing to a production billing provider. Resend provides email delivery with a verified sending domain. Supabase Auth provides federated login but does not replace local RBAC without a migration design. Cloudflare R2 holds immutable updates and temporary objects in separate buckets with lifecycle rules. Cloud KMS selection depends on the deployer's cloud account and key-management requirements. Provider accounts, domain ownership and hardware/platform support require external setup. Never configure secrets in chat or source.
