# Documentation Index

Required documentation set (brief §56) and its status. Every doc is versioned with the code; trust-boundary changes require an ADR.

| Required document                                                   | Status                                                                    | Location                                                                                                     |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Architecture Overview (context, bounded contexts, trust boundaries) | ✅ V1                                                                     | [architecture/01-system-context.md](architecture/01-system-context.md)                                       |
| Domain Model                                                        | ✅ V1                                                                     | [architecture/02-domain-model.md](architecture/02-domain-model.md)                                           |
| License State Machine                                               | ✅ V1 (§5 of the domain model)                                            | [architecture/02-domain-model.md](architecture/02-domain-model.md#5-license-state-machine)                   |
| Database Model                                                      | ✅ V1                                                                     | [architecture/04-database-model.md](architecture/04-database-model.md) + `services/platform-api/migrations/` |
| Threat Model                                                        | ✅ V1 (licensing/activation)                                              | [threat-models/01-v1-licensing-and-activation.md](threat-models/01-v1-licensing-and-activation.md)           |
| API Specification                                                   | ✅ V1                                                                     | [api/openapi.yaml](api/openapi.yaml), [api/lease-test-vectors.json](api/lease-test-vectors.json)             |
| Key Management Design                                               | ✅ V1                                                                     | [security/key-management.md](security/key-management.md)                                                     |
| Invariant traceability                                              | ✅                                                                        | [security/invariants-traceability.md](security/invariants-traceability.md)                                   |
| ADRs                                                                | ✅ 001–004                                                                | [adr/](adr/)                                                                                                 |
| Incident Response Procedures                                        | 🟡 drafted, unrehearsed                                                   | [runbooks/incident-response.md](runbooks/incident-response.md)                                               |
| Recovery Procedures                                                 | 🟡 drafted; needs PG adapters                                             | [runbooks/recovery.md](runbooks/recovery.md)                                                                 |
| Status and handoff                                                  | ✅                                                                        | [architecture/05-v1-status-and-handoff.md](architecture/05-v1-status-and-handoff.md)                         |
| Device Trust Model                                                  | ⏳ Milestone 2                                                            | —                                                                                                            |
| Policy Engine Design                                                | ⏳ Milestone 2 (`AccessEvaluator` seam documented in the domain model §4) | —                                                                                                            |
| Update Trust Model                                                  | ⏳ Milestone 3                                                            | —                                                                                                            |

Architecture decision records:

1. [ADR-001 — Modular monolith, server-authoritative trust platform](adr/ADR-001-architecture.md)
2. [ADR-002 — Offline lease format](adr/ADR-002-signed-lease-format.md)
3. [ADR-003 — TypeScript on Node with native type stripping](adr/ADR-003-typescript-runtime-and-tooling.md)
4. [ADR-004 — Authentication modes by endpoint class](adr/ADR-004-authentication-modes.md)
