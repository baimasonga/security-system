# ADR-013 — Validation writes, current subscription plans, and bounded leases

- Status: Accepted · Date: 2026-10-11 · Affects trust boundaries: **yes**

## Context

Review reproduced three defects on the licensing lifecycle: validation could write a stale
activation over a concurrent deactivation; subscription plan changes did not change the plan
used by subsequent leases; and accepted plan data could exceed the SDK's 16 KiB JWS limit.

## Decision

- Validation uses `touchActiveActivation(orgId, activationId, installationId, now)`: a single
  conditional write that changes only `lastValidatedAt` on a currently active activation with
  the proven installation binding. It returns the current row, or no row when deactivation,
  revocation, or reinstallation won the race. Validation never restores status, installation,
  or lease metadata from its earlier snapshot. This retains ADR-009's five-statement budget.
- For subscription-backed licenses, the subscription's current plan is authoritative in
  `findLicenseContext`, customer views, activation, validation, and refresh. The license's
  stored `planId` remains its issued-plan reference; perpetual/canary licenses keep that plan.
  Operator subscription plan changes must stay within the current plan's product. Reads
  overlapping a plan change may observe the prior snapshot; reads after commit use the new plan.
  Existing signed offline leases retain their original entitlements until their bounded expiry.
  Downgrades do not evict already active devices; the new limit blocks additional devices.
- Preserve the existing 16 KiB verifier limit and lease schema. Limit the serialized resolved
  `{ent, cap}` snapshot to 8 KiB, leaving room for base64 expansion and binding/header claims.
  Enforce this on plan creation/edit and after merging per-license overrides. Signing also
  rejects a compact JWS exceeding the verifier limit before invoking key custody, so unusual
  metadata or legacy stored data cannot produce an unverifiable committed lease.

## Consequences and verification

No schema migration or privilege expansion is needed. Both store adapters share contracts for
conditional validation writes and current-plan resolution. Regression tests inject state changes
between proof/context reads and the validation write; downgrade tests check leases, customer
views, and device limits. Size tests cover rejected plan/override writes, accepted large leases,
and the signing boundary. Required validation includes both PostgreSQL roles and representative
activation/refresh/hot-license loads; measured results belong in the performance report.

Oversized legacy plans or overrides must be reduced by an operator; they fail closed on issuance.
This deliberately rejects oversized configuration rather than raising limits in deployed SDKs.
