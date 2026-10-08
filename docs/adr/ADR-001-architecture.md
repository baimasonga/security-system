# ADR-001 — Modular monolith, server-authoritative trust platform

- Status: Accepted
- Date: 2026-10-08
- Deciders: platform team
- Affects trust boundaries: **yes**

## Context

We need one platform that provides identity, licensing, entitlements, device
trust, secure updates, telemetry and enterprise controls to all current and
future desktop and web products. The mandate is explicit: do not reduce this to
a license-key server, do not over-split into microservices, prefer boring and
auditable security, and keep operating cost low.

## Decision

1. **Modular monolith** (`services/platform-api`) composed from independent
   packages that map 1:1 to bounded contexts (see
   [01-system-context](../architecture/01-system-context.md)). Packages
   communicate through explicit TypeScript interfaces (ports); dependency
   direction is enforced mechanically (`tools/check-boundaries.mjs`).
   Extraction to a service is allowed only for a demonstrated operational
   reason (independent scaling, blast-radius isolation of signing).
2. **Server is the only authority** for commercial and privileged decisions.
   Clients receive _signed evidence_ (leases, later capability tokens and trust
   passports) that is verifiable offline with public keys only.
3. **Commercial concepts stay separate**: Subscription → License → Entitlements
   → Capabilities → Consumption. Plan behavior is resolved server-side from a
   versioned plan; clients never switch on plan names.
4. **Decisions are policy outputs**, not booleans: the domain exposes an
   `AccessEvaluator` returning `ALLOW | OBSERVE | STEP_UP_AUTH | RESTRICT |
SUSPEND | DENY` + reason codes. V1 emits deterministic ALLOW/DENY; the
   adaptive trust engine (Milestone 2) swaps in behind the same port.
5. **Ports for every external dependency** (store, clock, signer, audit sink,
   telemetry sink). V1 ships an in-memory adapter (used by unit/integration
   tests) and a PostgreSQL schema validated by migration tests. PostgreSQL
   remains the system of record; adapters follow.
6. **Fail-closed for hard invariants, fail-soft for user data**: signature,
   binding, revocation and tenant-isolation failures deny. Licensing failures
   never delete or lock user documents; they surface machine-readable states.
7. **Tenant isolation at the data layer**: every repository method takes an
   `orgId`; composite foreign keys keep child rows in the parent's org.
   Unauthorized object access returns 404.

## Alternatives considered

| Option                                        | Rejected because                                                                        |
| --------------------------------------------- | --------------------------------------------------------------------------------------- |
| Microservices from day one                    | Operational cost and distributed-failure surface far exceed V1 needs                    |
| Third-party licensing SaaS                    | Cannot express trust passport / adaptive policy / provenance; vendor owns signing trust |
| Client-side license checks as primary control | Patchable by definition; contradicts invariant "clients are untrusted"                  |
| JWT libraries for leases                      | Larger attack surface than a 100-line EdDSA-only verifier (see ADR-002)                 |

## Consequences

- One deployable, simple local dev, easy transactions across contexts.
- Boundaries are real (lint-enforced), so extraction later is mechanical.
  − Single process holds the signing capability in V1; mitigated by the `Signer`
  port (KMS/HSM later) and key-purpose separation. Tracked in key-management doc.
  − The in-memory adapters are reference implementations for tests; production uses the
  PostgreSQL adapters (ADR-005), which are held to the same contract tests.

## Rollout / rollback

V1 has no production users. Schema migrations are forward-only, numbered, and
each ships with a tested down-path or documented restore procedure.
