# ADR-002 — Offline lease format: compact JWS, EdDSA only, device-bound

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes**

## Context

Desktop apps must work offline for a policy-defined period, with entitlements
that cannot be edited or copied to another machine.

## Decision

- Lease = **compact JWS** (`base64url(header).base64url(payload).base64url(sig)`),
  header `{"alg":"EdDSA","typ":"lease+jws","kid":"<key id>"}`.
- **Ed25519 only.** The verifier hard-pins `alg`; there is no algorithm
  negotiation, no `none`, no HMAC. Implemented on `node:crypto` (no JWT lib).
- Verifier enforces: size cap, exactly three segments, canonical base64url,
  `typ`, `alg`, known `kid` that is in a _verifiable_ lifecycle state, then
  claims-level checks (issuer, audience/product, `nbf/iat/exp` with bounded skew,
  installation + device-key binding).
- Payload (schema version `v:1`): `jti, iss, aud, lic, org, prd, pln, plv, act,
inst, dev, cnf.jkt, kind, tier, ent, cap, iat, nbf, refresh_after, exp`.
  `cnf.jkt` is the RFC 7638-style SHA-256 thumbprint of the device public key
  (confirmation claim in the spirit of RFC 7800).
- Lease TTL comes from **policy configuration** per tier (defaults: trial 3d,
  standard 14d, professional 30d, business 60d, enterprise configurable), not
  constants in code paths.
- The server authorizes refresh by a device signature over a single-use
  challenge; a lease alone is never sufficient to obtain another lease.
- Trust distribution: clients ship a **trust bundle** (list of `{kid, jwk}`)
  and may refresh it from `GET /v1/keys/trust-bundle`; bundles from the network
  are accepted only if every key is signed-off by a pinned root in a later
  milestone — V1 pins the bundle at build time. Revoked keys are removed from
  the bundle; leases signed by them stop verifying.

## Consequences

- Small, auditable verifier; no JWT-library CVE class (alg confusion, kid
  injection) because there is no negotiation.
- Rotation: new `kid` active, old `deprecated` (verify-only) until its last
  lease expires, then `archived`.
  − Revocation of an already-issued lease is bounded by TTL while offline (R-1).
