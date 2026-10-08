# Key Management Design (V1)

Applies the `cryptographic-key-management` skill. Implementation:
`packages/crypto/src/keyring.ts` (lifecycle), `signing.ts` (custody),
`jwk.ts` / `verify.ts` (verification-only surface shared with clients).

## 1. Key and secret inventory

| Item                                                        | Purpose                                        | Owner                     | Algorithm      | Storage (dev → prod target)                                                             | Rotation                                                               | Blast radius if compromised                                                                      |
| ----------------------------------------------------------- | ---------------------------------------------- | ------------------------- | -------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **License-signing key** (`purpose: license`)                | Signs offline leases                           | Platform / security owner | Ed25519        | Ephemeral in-process (dev) → KMS/HSM non-exportable key behind `KeyCustody` (prod)      | Planned every 12 months + on suspicion; overlap window = max lease TTL | Anyone can forge leases for **every product** until clients drop the key from their trust bundle |
| **License-key pepper** (`LICENSE_KEY_PEPPER`)               | HMAC for stored license-key digests            | Platform                  | HMAC-SHA-256   | Env/secret store, ≥ 32 chars                                                            | On suspicion (requires re-keying digests, see §4)                      | DB leak + pepper leak enables offline guessing of keys (125-bit keys keep this infeasible)       |
| **Pseudonym key** (`PSEUDONYM_KEY`)                         | Pseudonymizes identifiers in telemetry/signals | Platform                  | HMAC-SHA-256   | Env/secret store                                                                        | Annually (breaks correlation continuity, acceptable)                   | De-pseudonymization of analytics subjects                                                        |
| **Device key**                                              | Proves possession; binds leases                | The customer's device     | Ed25519        | Software key in host `SecureStore` (V1) → TPM / Secure Enclave / Keystore (Milestone 2) | Re-activation                                                          | One device identity                                                                              |
| Session tokens, challenge nonces                            | Authentication, single-use proofs              | —                         | 256-bit random | Only SHA-256 digests stored                                                             | Expiry (12 h / 5 min)                                                  | One session / one challenge                                                                      |
| Root / release / capability / tenant / data-encryption keys | Later milestones                               | —                         | —              | **Not created in V1.** Each gets an entry here and an ADR when introduced               | —                                                                      | —                                                                                                |

Rules (enforced where noted):

- No private key material in the repository — `tools/check-boundaries.mjs` fails the build on any PEM private-key block; `.gitignore` excludes `*.pem`, `*.key`, `secrets/`; CI runs a secret scanner.
- No signing code in client artifacts — `sdk-core` may import only `@trust/crypto/verify` (boundary checker).
- One key per purpose. A second purpose (capability tokens, release signing) must be a **separate** key with its own `KeyPurpose`, never reuse the license key.
- Dev/test keys are ephemeral and never trusted by production verifiers.

## 2. Lifecycle (implemented and tested)

```
generate → activate → (use) → deprecate → revoke → archive → destroy
   │                      └── rotation: activate(new) automatically deprecates the old one
```

| State      | May sign                          | May verify (in trust bundle) | Notes                                                                                       |
| ---------- | --------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------- |
| generated  | no                                | no                           | cannot sign until activated                                                                 |
| active     | **yes** (exactly one per purpose) | yes                          | `activeKeyId()` throws if none → signing **fails closed**                                   |
| deprecated | no                                | yes                          | keeps old leases valid until they expire                                                    |
| revoked    | no                                | **no**                       | immediate loss of trust: leases signed by it stop verifying once clients refresh the bundle |
| archived   | no                                | no                           | kept for forensics                                                                          |
| destroyed  | no                                | no                           | private material removed from custody; irreversible                                         |

Illegal transitions throw. Every transition emits a `KeyLifecycleEvent`; the
platform writes it to the audit log (`key.generate|activate|deprecate|revoke|…`)
with `kid`, purpose, from/to and reason — never key material.

Tests: `packages/crypto/test/jws.test.ts` (KeyRing lifecycle), `packages/licensing/test/activation.test.ts`
("signing-key rotation", "fails closed"), `packages/sdk-core/test/lease-verifier.test.ts` ("revoked signing key").

## 3. Rotation procedure (routine)

1. `ring.generate('license')` → new `kid` in state _generated_; publish nothing yet.
2. `ring.activate(newKid, reason)` → the old key becomes _deprecated_ in the same call; new leases are signed by the new key.
3. Clients fetch `GET /v1/keys/trust-bundle` (cacheable 5 min) and learn the new `kid`; old leases keep verifying (deprecated keys stay in the bundle).
4. After `max lease TTL` (default enterprise: 90 days) plus margin, `deprecate → revoke → archive` the old key.
5. Verify: audit log shows the `key.*` events; `activeKeyId('license')` is the new key; a refresh yields a lease whose header `kid` is the new key.

> **V1 limitation:** the trust bundle shipped inside the client is pinned at build time (ADR-002). Rotation therefore needs either a client release that includes the new public key **before** step 2, or the signed bundle-update mechanism planned with Milestone 3 (root → online key delegation). Until then, rotate only with a client release in the field that already trusts the new key.

## 4. Compromise procedure (emergency)

See [incident-response runbook](../runbooks/incident-response.md#a-license-signing-key-compromise).
Summary: `revoke(kid, reason)` (dual control from Milestone 6) → activate a
pre-generated standby key → bundle drops the old key → every device must
refresh; legitimate devices keep working through the refresh, forged leases die.

Pepper compromise: rotate the pepper and re-issue license keys (digests cannot be
recomputed without plaintext). Because keys are only shown once, this is a
customer-visible event — hence the 125-bit key space as the primary defense.

## 4a. Persistence and restarts (ADR-005)

Key **metadata** (public key, state, timestamps) is stored in `signing_keys`; private
material is never stored in the database. At start-up the key ring restores the
records and attaches the configured private key (`LICENSE_SIGNING_KEY_FILE`/`_PEM`),
matching it by its deterministic `kid`:

| Configured key is…                   | Start-up behaviour                                                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| unknown                              | imported, activated; the previously active key (if any) becomes `deprecated` — this _is_ the routine rotation path |
| the current active key               | attached, normal start                                                                                             |
| `deprecated` (rotated out)           | **refuses to start**                                                                                               |
| `revoked` / `archived` / `destroyed` | **refuses to start**                                                                                               |

Tests: `services/platform-api/test/db/adapters.db.test.ts` ("container restart").

## 5. Gaps (tracked)

- Production custody is still an in-process software key loaded from a secret mount. The
  `KeyCustody` interface is the seam for KMS/HSM; implementing it is a
  prerequisite for production.
- No offline root or key-delegation (Milestone 3). Until then the license key is a
  single online trust anchor.
- Standby-key pre-generation and a rehearsed rotation drill are not yet automated.
