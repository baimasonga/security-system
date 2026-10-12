# ADR-017: Authenticator MFA

Status: accepted.

Password login accepts an optional authenticator or recovery code. Enrolled users receive no session until both factors succeed. Enrollment requires password reauthentication and a first valid TOTP; a pending enrollment expires after ten minutes and never replaces an enabled factor. Confirmation and disabling revoke all sessions atomically with audit. Password reset preserves enabled MFA and discards pending enrollment.

Use RFC 6238 SHA-1, six digits, thirty-second steps, with one adjacent step of clock tolerance. The last accepted counter is persisted under the user row lock, preventing concurrent replay. Ten recovery codes each have 128 bits of randomness, are shown once, and only their digests are retained; consumption shares the session transaction. TOTP secrets are encrypted using AES-256-GCM with a separately supplied stable MFA_ENCRYPTION_KEY; associated data binds ciphertext to the user and purpose. Losing or replacing this key prevents factor verification: never fall back to password-only login. Keep encrypted backups and the key under separate access controls. Key rotation needs a future explicit re-encryption tool.

No QR service receives provisioning secrets; the portal presents a manual setup key. Codes, passwords and secrets never enter audit metadata. Login failure lockout and route throttling apply. Enrollment/disable check a live session again under the user lock to close revocation races. All factor writes are audited in the same transaction.

REQUIRE_OPERATOR_MFA=true prevents unenrolled operators from administration while permitting account access to enroll. Default false supports staged rollout: enable after all operators enroll and store recovery codes. This is not phishing-resistant MFA: passkeys and privileged step-up/dual control remain separate work. Email recovery does not remove MFA. No support bypass or automatic factor recovery is introduced. MFA management requires password plus a code when enabled; disable requires a reason. A failed management attempt contributes to the same account lockout as login.
