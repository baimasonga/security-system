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
| ADRs                                                                | ✅ 001–007                                                                | [adr/](adr/)                                                                                                 |
| Load & soak test report                                             | ✅ V1 (single shared VM — see its limits section)                         | [performance/load-test-v1.md](performance/load-test-v1.md)                                                   |
| Capacity & monitoring runbook                                       | ✅                                                                        | [runbooks/capacity-and-monitoring.md](runbooks/capacity-and-monitoring.md)                                   |
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
5. [ADR-005 — PostgreSQL adapters](adr/ADR-005-postgresql-adapters.md)
6. [ADR-006 — Atomic audit and transaction retry](adr/ADR-006-atomic-audit-and-transaction-retry.md)
7. [ADR-007 — Shared license lock; retention off the request path](adr/ADR-007-locking-and-retention-under-load.md)
8. [ADR-008 — Partitioned audit chains](adr/ADR-008-partitioned-audit-chains.md)
9. [ADR-009 — Fewer database round trips per device flow](adr/ADR-009-fewer-database-round-trips.md)
10. [ADR-010 — External audit anchor](adr/ADR-010-external-audit-anchor.md)
11. [ADR-011 — Shared abuse-control state](adr/ADR-011-shared-abuse-control-state.md)
12. [ADR-012 — Managed PostgreSQL profile (Supabase)](adr/ADR-012-managed-postgres-profile.md) · [Supabase deployment guide](deploy/supabase.md) · [First deploy checklist](deploy/first-deploy.md) · [Railway + R2](deploy/railway.md)

Current browser and identity work:

- [ADR-015 — Browser portal](adr/ADR-015-browser-portal.md)
- [ADR-016 — Email verification and password recovery](adr/ADR-016-identity-recovery.md)
- [ADR-024 — Capability tokens for processing services](adr/ADR-024-capability-tokens.md)
- [ADR-023 — Passkeys (WebAuthn)](adr/ADR-023-passkeys.md) · [threat model](threat-models/04-passkeys.md)
- [ADR-022 — Privileged operations: dual control, JIT grants, freeze, break-glass](adr/ADR-022-privileged-operations.md) · [threat model](threat-models/03-privileged-operations.md)
- [ADR-021 — File sharing, document publication and short links](adr/ADR-021-file-sharing-and-short-links.md) · [architecture, data model, cost model and phased plan](architecture/10-file-sharing-and-short-links.md) · [threat model](threat-models/02-file-sharing-and-short-links.md) · [retention policy](security/sharing-retention.md) · [API guide](api/sharing.md)
- [Feature implementation program](architecture/08-feature-program.md)
- [Proposed advanced requirements](architecture/09-advanced-feature-requirements.md)

Portal, operator console, catalog and software-device demo are implemented. Email recovery requires optional Resend configuration. Authenticator MFA, passkeys and privileged operations (dual control, JIT grants, freeze, break-glass) are implemented. Advanced billing, device trust, workspace and the remaining items in the feature program are still tracked as remaining work, not completed features.
