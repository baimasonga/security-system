# ADR-007 — Shared license lock for refresh; retention off the request path

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (license-state consistency, data retention)
- Evidence: [load-test report](../performance/load-test-v1.md). Builds on [ADR-005](ADR-005-postgresql-adapters.md) and [ADR-006](ADR-006-atomic-audit-and-transaction-retry.md).

## Context

Load testing (open-loop, real server process, real PostgreSQL with `fsync` on) showed:

1. **Refresh serialized per license.** ADR-006 made `refresh` lock the license row `FOR UPDATE` and re-check
   access under the lock. For a single hot license (large enterprise, post-outage reconnect storm) every refresh
   queued behind the previous one: p99 123 ms vs 25 ms at 200 refreshes/s, and a lower throughput ceiling (223 vs
   338 rps) than the same load spread over many licenses.
2. **Retention on the request path.** Every challenge issue ran `DELETE … WHERE expires_at < $1`, with no index on
   `expires_at`, so its cost grew with the table (one row per device call).
3. **Concurrent statements on one connection.** Service code issued `Promise.all` reads inside a transaction;
   the driver queues them implicitly today but warns that this is removed in `pg@9`.

## Decision

- **Refresh takes a shared (`FOR SHARE`) license lock.** It still guarantees the license cannot change state
  underneath the issuing transaction (activate and every operator state change take `FOR UPDATE`, which conflicts
  with shared locks), so the ADR-006 guarantee — _no lease is issued from a stale view of the license_ — is
  unchanged, but concurrent refreshes no longer block each other. Lock order stays license → activation; a
  shared lock is never upgraded. Port method: `findLicenseForShare` (contract-tested; the PostgreSQL
  concurrency semantics are tested directly: shared holders coexist, an exclusive locker waits for all of them).
  A service-level test asserts that refresh uses the shared method and activation the exclusive one.
- **Retention moves to a background job** (`runMaintenance`, run by `startMaintenance` every
  `MAINTENANCE_INTERVAL_SECONDS`, default 60): batched, bounded deletes of challenges expired longer than
  `CHALLENGE_RETENTION_SECONDS` (default 1 h — long enough that replay of a spent nonce is still reported as
  _used_, never _missing_) and lease records expired longer than `LEASE_RETENTION_SECONDS` (default 90 d, forensic
  history only; the audit log keeps `lease.issued` permanently). Migration `0002` adds `expires_at` indexes.
  Failures are counted (`maintenance_runs_total{outcome}`) and logged; the job never overlaps itself and is safe
  to run on several instances.
- **Audit head read shares a round trip with the chain lock.** `appendAuditInTx` sends
  `SELECT pg_advisory_xact_lock(k); SELECT seq, hash … ORDER BY seq DESC LIMIT 1` as one simple-query message. They
  stay two _statements_ on purpose: in READ COMMITTED each statement takes its own snapshot, so the head is read
  **after** the lock is granted and includes the previous holder's commit. Merging them into one statement would use
  a snapshot taken before the wait and fork the chain (a 240-append / 4-pool test fails if that is done — verified
  by mutation). Measured gain: +19 % on loopback, +43 % at ≈ 2 ms RTT. The chain lock is still held across
  lock/head, insert and commit, so the ceiling remains ≈ 1/(3·RTT + fsync); the structural fix (per-tenant chains or a
  database-side append) is recorded in the load-test report §7 and needs its own ADR.
- **Transaction reads are explicitly serialized per connection** (`serialized()`), so correctness no longer
  depends on the driver's deprecated implicit queueing.
- **Operational metrics** are part of the product surface (operator-only `/v1/admin/metrics`, JSON or Prometheus):
  request and transaction latency, retries/exhaustion by SQLSTATE, audit-lock wait, pool pressure, event-loop delay,
  maintenance outcomes. Labels are route _templates_ and enumerated outcomes only (test-enforced: no ids, emails
  or tokens).

## Consequences

- Hot licenses scale like spread load; retention cost no longer scales with traffic or blocks requests.
- Retry exhaustion, pool waits and audit-chain contention are now visible instead of inferred.
  − Spent challenges and expired lease records now persist until the next maintenance pass; storage is bounded by
  `rate × (TTL + retention)`, not by request-path deletes. Operators must keep the job healthy (alert on
  `maintenance_runs_total{outcome="error"}`).
  − A shared lock still blocks while an activation or operator change holds the exclusive lock; during a
  300-device activation stampede on one license refreshes of that license wait (seconds, bounded by the stampede).
  − **A configuration knob that never reaches the service is a silent failure.** The first soak ran with the
  default retention because a patch silently did not apply; the fix added a test that proves each operator knob
  changes behaviour (`maintenance.test.ts`). New knobs need the same test.
