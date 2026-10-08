# ADR-004 — Three authentication modes, selected by endpoint class

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes**

## Context

The platform serves humans (portal/console), software on customer devices, and
anonymous bootstrap calls. One mechanism for all would either force bearer
secrets onto devices or give humans device-style credentials.

## Decision

| Class               | Endpoints                                                                                  | Authentication                                                                                                                                                                                      | Why                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Session** (human) | `/v1/auth/*`, `/v1/organizations/**`, `/v1/entitlements`, `/v1/licenses/activate`          | Opaque 256-bit bearer token (SHA-256 stored), 12 h absolute expiry, revocable; org RBAC checked per request                                                                                         | Simple, revocable, no cookies ⇒ no CSRF surface                                                              |
| **Operator**        | `/v1/admin/**`                                                                             | Session **plus** server-side `platform_admin` re-check on every request; mandatory `reason` on mutations; path always names the tenant                                                              | Demotion is effective immediately; no cross-tenant wildcards; later replaced by JIT elevation + dual control |
| **Device**          | `/v1/licenses/{validate,refresh,deactivate}`                                               | **No bearer token.** Request carries `activation_id`; authority is an Ed25519 signature, by the device key registered at activation, over a single-use, purpose-bound, installation-bound challenge | A lease or activation id leaked from disk is not a credential; the device key is                             |
| **Anonymous**       | `/v1/auth/{register,login}`, `/v1/devices/challenges`, `/v1/keys/trust-bundle`, `/healthz` | None; strict schemas, per-route rate limits, per-installation challenge cap                                                                                                                         | Bootstrap only; each returns no tenant data                                                                  |

Activation is the one flow that needs **two** factors of different kinds: a user
session (who) and a device proof (which key). The license key selects the license
but never authorizes.

## Consequences

- Compromising a lease file, activation id, license key or trust bundle individually yields nothing usable.
- Device calls survive signing-key rotation (they do not depend on parsing an old lease).
  − Device endpoints cannot be tenant-scoped by session; org is derived from the activation record (documented, tested in `tests/security`).
  − Bearer sessions remain stealable (R-4); passkeys/DPoP-style binding are planned.
