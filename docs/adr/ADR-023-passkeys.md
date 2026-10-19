# ADR-023: Passkeys (WebAuthn)

Status: accepted. Affects trust boundaries: **yes** (account authentication).

## Context

Password + authenticator code (ADR-017) can still be phished: a fake site relays both. The requirements in
[architecture/09](../architecture/09-advanced-feature-requirements.md#identity) ask for passkeys using WebAuthn with
challenge expiry, origin/RP binding and verified signature counters — no custom protocol.

## Decision

Implement the WebAuthn Relying Party side ourselves (no new dependency), in `packages/auth/src/webauthn.ts`: a
bounded CBOR decoder, COSE key import and the registration/assertion checks of WebAuthn Level 2 §7.1–7.2 that apply
to a server that does **not** trust attestation.

Configuration: `WEBAUTHN_RP_ID` (a registrable domain, e.g. `rokela.example`) and `WEBAUTHN_ORIGIN` (the exact portal
origin, e.g. `https://app.rokela.example`; its host must be the RP ID or a subdomain of it). Production requires an
`https:` origin. Without both, passkeys are disabled (`409`), nothing else changes.

### Registration (signed-in user)

1. `POST /v1/auth/passkeys/register/begin {password}` — password re-authentication (as for MFA enrollment, it counts
   toward the lockout), then a creation challenge: 32 random bytes, stored only as a SHA-256 digest, bound to the user
   and the session, valid for 5 minutes. Options require a discoverable credential and user verification, offer
   EdDSA, ES256 and RS256, exclude the user's existing credentials, and ask for `attestation: "none"`.
2. `POST /v1/auth/passkeys/register/finish {name, credential}` — the challenge is consumed first (single use, even
   when verification then fails). Checks: `clientData.type = webauthn.create`; challenge; exact origin;
   `crossOrigin` not true; `rpIdHash = SHA-256(RP ID)`; flags user-present, user-verified and attested-credential-data;
   supported algorithm and a well-formed key; credential id ≤ 1023 bytes and not registered to anyone. The
   attestation statement is **not** verified and never treated as hardware evidence: the passkey proves possession
   of a key, nothing about the device (device trust is a separate milestone).

### Sign-in (no password)

`POST /v1/auth/passkeys/login/begin` returns a challenge (5 minutes, single use, not bound to an account — the
browser offers the user's discoverable credentials). `POST /v1/auth/passkeys/login/finish` consumes the challenge,
then checks: credential known; account active; `webauthn.get`; challenge; origin; `rpIdHash`; user-present and
user-verified; the signature over `authenticatorData ‖ SHA-256(clientDataJSON)` with the stored key; the user handle,
when sent, equals the credential's user. **Signature counter:** when either the stored or the new counter is
non-zero, the new one must be strictly greater; otherwise sign-in is refused, a `passkey_counter_regression` security
signal is raised and the event audited (a cloned authenticator). Counters that are always zero (many synced
passkeys) are accepted as the specification allows. Every failure returns the same `401`.

A user-verified passkey sign-in is phishing-resistant multi-factor authentication, so it does not additionally ask
for the authenticator code. Operator step-up for privileged approvals (ADR-022) still uses the authenticator code.

### Management

`GET /v1/auth/passkeys` lists name, creation and last use (never keys). `POST /v1/auth/passkeys/{id}/delete
{password}` removes one after password re-authentication. All writes are audited in their transaction. Password reset
and MFA changes do not remove passkeys. Expired challenges are purged by maintenance.

## Consequences

- No third-party WebAuthn library: the parser is small, bounded (size, depth, no indefinite lengths) and fuzzed with
  malformed input in tests; it is the most security-sensitive new code.
- Attestation-based device claims are out of scope by design.
- `REQUIRE_OPERATOR_MFA` still requires an authenticator app for operators (step-up uses it).
