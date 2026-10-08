# ADR-009 — Fewer database round trips per device flow

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **no** (same locks, same decisions, same audit);
  one durability trade-off for _product telemetry_ (below).
- Addresses load-test finding **LT-5** and recommendation 2 of the [load-test report](../performance/load-test-v1.md).

## Context

A refresh flow (challenge request + refresh request) cost **21** statements, an activation **23**, a validation **11**
(`tests/integration/roundtrips.e2e.test.ts` traces them). Every statement is a network round trip and, inside a
transaction, keeps a pooled connection and the license/audit locks held longer. At 2 ms RTT that is ≥ 40 ms of pure
waiting per flow, and CPU on this box was dominated by driver and socket work, not by the application logic.

## Decision

Combine statements that were always issued together; **change no decision, lock, or audit event**.

| Change (store port)                                                                                                                                                                                                                                     | Replaces                                                                                 | Saves                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------- |
| `findLicenseContext(org, id, 'none'\|'share'\|'update')` — license + plan + product + subscription in one `SELECT … JOIN` with the same row lock on the license (`FOR SHARE OF l` / `FOR UPDATE OF l`)                                                  | `findLicense[ForShare\|ForUpdate]` + `findPlan` + `findProductById` + `findSubscription` | 3 per use (×2 on refresh before) |
| Refresh evaluates the license **once, under the shared lock**, instead of an unlocked pre-check plus a locked re-check. A refusal is recorded (audit `license.validation_failed`, telemetry) right after the rolled-back transaction, exactly as before | duplicate context read                                                                   | 1 + locking-free pre-check       |
| `findActivationWithDevice`                                                                                                                                                                                                                              | `findActivationForDeviceAuth` + `findDevice`                                             | 1                                |
| `insertChallengeIfBelow` (limit check + insert in one statement)                                                                                                                                                                                        | `countOutstandingChallenges` + `insertChallenge`                                         | 1 per challenge                  |
| `insertDevice` is one statement for both outcomes (inserted row, else the existing one); activation no longer pre-reads the device                                                                                                                      | `findDeviceByThumbprint` + `insertDevice`                                                | 1                                |
| `findActivationSlot` (this device's active activation + the license's active count)                                                                                                                                                                     | `findActiveActivation` + `countActiveActivations`                                        | 1                                |
| `recordLease` (lease row + activation lease fields in one statement)                                                                                                                                                                                    | `insertLease` + `updateActivation`                                                       | 1 per lease                      |
| `findSessionWithUser`                                                                                                                                                                                                                                   | `findSessionByTokenHash` + `findUserById`                                                | 1 per authenticated request      |
| Product telemetry is **buffered** and written in batches (`PgTelemetrySink`, ≤ 200 records or 500 ms, bounded at 10,000, flushed on shutdown)                                                                                                           | one `INSERT` per tracked event                                                           | 1 per flow                       |

Every new port method is in the contract suites, so the in-memory and PostgreSQL adapters must agree.

## What deliberately did not change

- Lock order (license → activation), lock strength per path (activation: `FOR UPDATE`, refresh: `FOR SHARE`), the
  audit write inside the same transaction (ADR-006/-008), single-use challenge consumption, proof verification order.
- **Security signals are still written before the request returns.** Only counters in `telemetry_events` are buffered.
- `BEGIN`/`COMMIT`/audit head lock/audit insert remain separate statements: the head must be locked and read before
  the event hash can be computed (ADR-008).

## Consequences

- Activation 23 → 14, refresh flow 21 → 10, validation 11 → 5 statements; shorter lock hold times; fewer pool checkouts.
- A round-trip budget test fails if a later change adds statements to a flow without updating the budget on purpose.
  − **A crash can lose up to ~500 ms of product telemetry** (never audit, never security signals). Failed batches are
  counted (`PgTelemetrySink.dropped`) and discarded; telemetry can no longer fail a request that already committed.
  − `insertChallengeIfBelow` is a soft limit under concurrency (as the count-then-insert it replaces was); rate limiting
  is the hard control.
  − The `join` reads make an inconsistent catalog (plan or product missing) look like "license missing"; foreign keys
  already make that state unreachable.
