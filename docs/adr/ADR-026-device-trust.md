# ADR-026: Device trust — passport, signals and a deterministic posture

Status: accepted. Affects trust boundaries: **yes** (device authorization).

## Context

[architecture/09](../architecture/09-advanced-feature-requirements.md#device-trust-and-policy): a device passport
combines key identity with verified attestation results where supported; no browser user agent or self-reported flag
counts as hardware evidence; signals have provenance, timestamps and retention bounds; deterministic rules return
ALLOW/OBSERVE/STEP_UP_AUTH/RESTRICT/SUSPEND/DENY with reasons; hard signature, tenant and revocation invariants
cannot be overridden by a score; clone suspicion triggers observation or step-up first, not data deletion; missing
evidence is labeled unknown.

## Decision

**Signals are what the server observed**, never what a device says about itself (`provenance: server_observed`
is the only value the schema allows):

| Signal                  | Observed when                                                                |
| ----------------------- | ---------------------------------------------------------------------------- |
| `installation_switch`   | the same device key is re-activated under a different installation id        |
| `installation_mismatch` | a device-authenticated call names another installation than its activation's |
| `invalid_device_proof`  | a proof signature does not verify with the device's registered key           |
| `step_up_completed`     | the person re-activated the device with their session and the license key    |

Each is kept 90 days, then purged by maintenance.

**Posture** (`evaluateDevicePosture`, pure and deterministic, in `packages/licensing/src/device-policy.ts`):

1. A license decision other than ALLOW is returned unchanged — and in the service the license is evaluated
   **before** posture is consulted, so a revoked license is always reported as revoked.
2. Only signals after the latest `step_up_completed` count.
3. Installation switches in 7 days: 1–2 → OBSERVE; ≥ 3 → STEP_UP_AUTH (possible clone).
4. Failed proofs (`invalid_device_proof`, `installation_mismatch`) in 24 hours: 1–9 → OBSERVE; ≥ 10 → RESTRICT.
5. Attestation: no verified adapter exists yet, so every device reports `attestation_unknown`; it is never
   treated as evidence either way (a future verified adapter can report `verified` or `failed`; failed → RESTRICT).
6. Nothing here produces SUSPEND or DENY: those stay operator decisions and license invariants. Nothing ever
   deletes data.

The posture is recomputed whenever a signal is recorded (rare) and stored per device with a `review_at` (when a
contributing signal leaves its window). The refresh path reads it in the same query that loads the activation and
device, so device trust adds no database round trip to refresh; a stale posture is recomputed on read.

**Enforcement** is staged with `DEVICE_POLICY`:

- `observe` (default): posture is computed, audited when it changes (`device.posture_changed`) and shown in the
  passport; nothing is blocked.
- `enforce`: STEP_UP_AUTH refuses refresh, validation and capability tokens with `403 step_up_required` (audited)
  until the person re-activates the device — the same proof as a first activation (session + license key + device
  key). Deactivation always works. RESTRICT keeps the device working but caps its offline leases at
  `restrictedLeaseTtlSeconds` (default 24 hours).

**Passport**: `GET /v1/organizations/{org}/devices/{device}/passport` (members with `device:read`) and the operator
equivalent show the key algorithm and thumbprint, attestation status with its reason, the posture with reasons and
mode, and the retained signals — never key material beyond the public thumbprint.

## Consequences

- A software device key copied together with its installation file is indistinguishable from the original; only
  hardware-backed keys with verified attestation can close that gap (tracked; the passport says `unknown`).
- Thresholds are constants in one file with tests; changing them is a reviewed code change, not a runtime knob.
