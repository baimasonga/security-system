# ADR-029: Cross-application operations and security monitoring

Status: **proposed; implementation contract to finalize in OPS-001**.
Date: 19 October 2026. Trust-boundary change: **yes**.

## Context

Warrior needs to monitor multiple applications and systems. The current Product
model is commercial licensing inventory, client telemetry is privacy-filtered usage
data, and the Security Center is account/device oriented. None alone supplies an
authenticated, durable operational event collector or cross-application incident lifecycle.

## Proposed direction

Add a separate operations domain with organization-scoped applications, environments,
components, integrations, events, health observations, alert rules and incidents.
Reuse identity, RBAC, audit and cryptographic primitives where appropriate. Link an
application to a licensing Product optionally; do not require licensing every system.

Separate backend integrations from user sessions and browser telemetry. Bind source
identity to a dedicated revocable credential. Use strict versioned schemas, durable
at-least-once acceptance, scoped deduplication and bounded source retry. Preserve
ADR-027 privacy controls and identify observation provenance. Begin with read-only
monitoring; do not introduce automated infrastructure changes through event payloads.

## Decisions required to accept this ADR

OPS-001 must specify, with rationale and negative examples:

- Inventory ownership, RBAC permissions and lifecycle; relationship to existing
  organizations, licensing Products and privileged-operation controls.
- Credential protocol, safe storage, scope, rotation overlap, revocation behavior,
  replay protection and one-time secret delivery.
- Exact versioned wire schema and route contract, batch/size/time limits, occurrence
  vs receipt time, source attribution, allowed metadata, idempotency/conflict behavior
  and durable acknowledgement semantics.
- Event retention/aggregation and how security evidence differs from lossy usage
  telemetry. Backpressure, quotas and outage behavior at source and collector.
- Probe ownership verification and SSRF defenses; health/stale/unknown semantics.
- Alert/incident state transitions, notification guarantees and audit requirements.
- Package placement consistent with the enforced dependency graph; migration and
  grants strategy, rollout/rollback and memory/PostgreSQL contract verification.

Do not infer accepted wire contracts or production readiness from this proposal.
The [program](../programs/operations-security.md) defines deliverables and sequencing.
