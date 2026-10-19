# Threat Model — Passkeys (ADR-023)

Test shorthand: **WA** = `packages/auth/test/webauthn.test.ts` (verification, CBOR, fuzz), **CON** =
`packages/auth/test/store-contract.ts` (memory + PostgreSQL), **PK** = `services/platform-api/test/passkeys.test.ts`
(also on PostgreSQL as superuser and as the least-privilege role). All rows below were mutation-checked (13 controls
broken one at a time; each made a test fail). The portal flow was exercised in Chromium with a virtual authenticator.

| ID    | Threat                                                   | Mitigation                                                                                                              | Evidence |
| ----- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------- |
| PK-1  | Phishing site relays a sign-in                           | `clientData.origin` must equal `WEBAUTHN_ORIGIN`; `rpIdHash` must be SHA-256 of `WEBAUTHN_RP_ID`; `crossOrigin` refused | WA, PK   |
| PK-2  | Replayed or stale assertion                              | 32-byte challenge, digest only, 5 minutes, consumed atomically once (also on failure); purpose-bound                    | CON, PK  |
| PK-3  | Registration finished from another session (CSRF/hijack) | Registration challenge bound to user and session; begin requires the password                                           | PK       |
| PK-4  | Forged signature / someone else's key                    | Signature over `authData ‖ SHA-256(clientDataJSON)` with the stored key; user handle must match                         | WA, PK   |
| PK-5  | Possession without the user (stolen unlocked key)        | User-present and user-verified flags required on registration and sign-in                                               | WA, PK   |
| PK-6  | Cloned authenticator                                     | Counter must increase when either counter is non-zero; refusal, audit and `passkey_counter_regression` signal           | WA, PK   |
| PK-7  | Malformed CBOR crashes or hangs the server               | Definite lengths only, item/depth/size limits, strict UTF-8, no tags/floats; 2,000-case fuzz                            | WA       |
| PK-8  | Account enumeration via sign-in errors                   | One generic `401 passkey sign-in failed` for every failure                                                              | PK       |
| PK-9  | One credential bound to two accounts                     | Credential id is the primary key; second registration → 409                                                             | CON, PK  |
| PK-10 | Removing another user's passkey                          | Delete scoped by user id; password re-authentication                                                                    | CON, PK  |
| PK-11 | Treating attestation as hardware evidence                | Attestation statement ignored by design; nothing about the device is claimed                                            | ADR-023  |

Residual risks: synced passkeys report a zero counter, so cloning of those cannot be detected (accepted by the
specification); a device that is unlocked and in an attacker's hands can sign in — that is the passkey model.
