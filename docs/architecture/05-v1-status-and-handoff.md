# 05 — V1 First-Slice Status and Handoff

Date: 2026-10-08 (updated after the PostgreSQL adapter slice) · Branch: `claude/sleepy-carson-l0if1k`

## 1. What is built and verified

The vertical slice from the brief — **Product → Plan → Subscription → License →
Device → Activation → Signed Offline Lease → Validation** — works end to end,
over real HTTP, with a client SDK, on **durable PostgreSQL storage** (ADR-005), and is covered by
**258 unit/integration/security tests on the in-memory adapters plus 150 tests on PostgreSQL**
(schema, adapters, port contracts, and the licensing/API/security/end-to-end suites re-run against
PostgreSQL), all passing. Also passing: `tsc`, ESLint
(+ security plugin), Prettier, the architecture-boundary check, `npm audit`
(0 vulnerabilities), and a clean `npm ci --omit=dev` start-up.

| Area                                             | State                                                                                                                                                    |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity (register, login, sessions, orgs, RBAC) | Minimal V1: password (scrypt) + opaque revocable session; personal + team orgs; owner/admin/member                                                       |
| Catalog (products, versioned plans)              | Done; plan edits bump version and reach devices on refresh without a client release                                                                      |
| Subscriptions                                    | Operator-managed state machine incl. dunning window; billing-provider webhooks are a later seam                                                          |
| Licenses                                         | subscription / trial / perpetual / canary; suspend / reinstate / revoke; effective status computed (no cron needed)                                      |
| Entitlements                                     | Pure resolver (plan version + per-license overrides) → entitlements, capabilities, device limit                                                          |
| Device activation                                | Session + license key + single-use challenge proof-of-possession; idempotent re-activation; race-free device limit; deactivate by device / owner / admin |
| Signed offline leases                            | Compact JWS, EdDSA only, bound to product + installation + device key; TTL from policy per tier; capped by entitlement end                               |
| Validation / refresh                             | Device-signature authenticated; reflects revocation, suspension, subscription lapse, plan version, key rotation                                          |
| Trials                                           | One per (product, org) and (product, user), server-side                                                                                                  |
| Canary licenses                                  | Indistinguishable from unknown keys; high-severity signal; denied twice (activation path + policy)                                                       |
| Audit                                            | Hash-chained, tamper-evident, verified by test and by endpoint; DB triggers make it append-only                                                          |
| Telemetry / security signals                     | Allow-listed attributes, pseudonymized subjects, redaction safety net                                                                                    |
| Key management                                   | Full lifecycle state machine; trust bundle; fail-closed signing; KMS-ready `KeyCustody` seam                                                             |
| Client SDK (`sdk-core`)                          | Device key, lease verifier (skew/rollback aware), API client with offline `getEntitlements`; verification-only crypto import enforced                    |
| API contract                                     | OpenAPI 3.1 with a drift test (code ⇄ spec) and cross-language lease test vectors                                                                        |
| Docs                                             | Context, bounded contexts, trust boundaries, domain model, state machine, DB model, threat model, ADR-001…004, key management, runbooks                  |

## 2. What is explicitly NOT done (do not assume otherwise)

1. **PostgreSQL storage is built but unproven at scale:** a 12–20 minute soak and single-VM load tests exist (see the report) but not a long soak, scale-out on real hardware, or failover/backup drills. Audit is atomic with every change and deadlocks are retried (ADR-006); the remaining storage-level risk is R-13 (a database superuser can rewrite history).
2. **CI and the Dockerfile have never been run** on GitHub Actions / a Docker daemon (unavailable here). Equivalent local checks were run. Expect small fixes on first run.
3. **No admin console, customer portal, or demo client app.** The HTTP API and SDK are complete enough to build them; `apps/*` directories are intentionally not scaffolded until they have content.
4. **Identity is minimal:** no email verification, MFA, passkeys, password reset, or refresh-token rotation. Operators are a flat role (no JIT / dual control).
5. **Capability tokens** (`POST /v1/capabilities/request`), consumption/quota tracking, seat assignment for enterprise orgs, offline _transfer_ flows, and the SDK methods `requestCapability / registerDevice / getTrustState / checkForUpdates / reportSecurityEvent` are not implemented (designs reserved in the domain model).
6. **Milestones 2–6** (hardware-backed keys, trust scoring, policy engine, clone detection, secure updates, SBOM/provenance, privacy firewall, workspace, JIT/dual control/freeze) are not started, per the brief's instruction not to start the advanced trust engine before the basic lifecycle is solid.
7. **No rehearsed runbooks**; no load/chaos testing; no external security review.
8. Trust-bundle distribution is pinned-at-build (ADR-002); safe key rotation across already-shipped clients needs the Milestone-3 signed bundle/root design.

## 3. Recommended next steps (in order)

1. **Act on the load-test findings** ([report](../performance/load-test-v1.md) §7): make audit appends cheaper to serialize (per-tenant chains or a database-side append — the single chain's ceiling falls with round-trip time to PostgreSQL), cut database round trips per flow, then validate scale-out and run a ≥ 24 h soak on production-like hardware; run the first backup-restore drill.
2. First CI run on GitHub; fix fallout; pin actions by SHA; enable branch protection + required checks + CODEOWNERS teams.
3. KMS/HSM `KeyCustody` implementation and a rehearsed rotation + compromise drill (closes the main gap in key-management §5).
4. Identity hardening: email verification, password reset, MFA/passkeys (operators first), refresh rotation.
5. Admin console + customer portal on the existing API (OpenAPI is the contract).
6. Milestone 2 (device trust, passport, trust engine, policy engine) behind the existing `AccessEvaluator` and `DeviceKey` seams.

## 4. Decisions worth challenging

| Decision                                                                              | Alternative                  | Why made                                                                                                    |
| ------------------------------------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Native Node type stripping, no build step (ADR-003)                                   | tsc/esbuild build            | Fewer moving parts, source = runtime; costs Node ≥ 22.18 and erasable-only TS                               |
| Own ~100-line EdDSA JWS instead of a JWT library (ADR-002)                            | `jose`                       | Smaller attack surface, no algorithm negotiation; costs owning the code (covered by vectors + tamper tests) |
| Activation id + device signature for refresh instead of lease-as-credential (ADR-004) | Present old lease            | Survives key rotation; leaked lease is inert                                                                |
| Tenant id in every customer path                                                      | Implicit tenant from session | Explicit, testable isolation; costs longer URLs                                                             |
| `GET /v1/entitlements?org_id&license_id`                                              | Header-based tenant          | Matches the brief's example endpoint while remaining tenant-explicit                                        |
