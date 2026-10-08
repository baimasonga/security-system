# ADR-011 — Abuse-control state shared across instances (rate limits and login lockout)

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (brute-force defence, availability under scale-out)
- Closes threat-model risks **R-7** and the per-instance part of **R-16**.

## Context

Two controls lived in process memory: the HTTP rate limiter (per-IP, per-route windows) and the failed-login
counters behind account lockout. With _N_ instances behind a load balancer an attacker gets up to _N_ × the intended
attempts (five guesses became five per instance), every restart or deploy reset the lockout, and counters grew without
bound (one entry per distinct email tried). The limiter's own store is pluggable; the lockout was not.

## Decision

1. **Account lockout moves into the identity store** (`login_failures`, migration 0005, part of the `AuthStore` port and
   its contract suite). Always on whenever persistence is PostgreSQL — it is authentication state, not a tuning choice.
   - Key = `sha256(normalized email)`: unknown accounts are counted identically (no existence oracle) and no address is stored.
   - `recordLoginFailure` is one atomic UPSERT: failures from any instance are never lost. Semantics are unchanged
     (5 failures → 15 min lock; the count keeps growing, so the first failure after a lock locks again; success clears).
   - Entries not touched for max(24 h, 2 × lockout) are deleted by background maintenance, so the table is bounded.
2. **HTTP rate-limit counters get a pluggable backend** (`RateBackend`) behind `@fastify/rate-limit`'s `store` option,
   one counter set per route as before:
   - `PgRateBackend`: one `INSERT … ON CONFLICT DO UPDATE` per limited request into an **UNLOGGED** table (`rate_limits`:
     no WAL, disposable, truncated by crash recovery). Windows are timed by the **database clock**, so instances with
     skewed clocks agree.
   - `ResilientRateBackend`: PostgreSQL first with a 300 ms budget; on error or timeout it counts in process memory and
     stays off the database for 5 s (circuit breaker). A database problem therefore never makes the limiter _weaker than
     it was before_ and never stalls requests; every fallback increments `rate_limit_fallback_total{reason}`.
   - `MemoryRateBackend` (bounded to 50,000 windows) is the fallback and the development default.
3. **Configuration** `RATE_LIMIT_STORE=memory|postgres`: defaults to `postgres` in production and `memory` otherwise;
   `postgres` requires `PERSISTENCE=postgres`. Choosing `memory` in production stays possible (a deliberately
   single-instance deployment) but then the limits are per instance — documented in the runbook.
4. Expired windows and stale lockout counters are purged by the existing maintenance loop (`maintenance_deleted_total{table=…}`).

## Cost (measured, see the load-test report §3.12)

Each limited request costs one extra round trip. A refresh flow (two requests) goes from 10 to 12 statements. On the
test box: no measurable change up to 400 flows/s at loopback latency; at a 2 ms round trip p50 rose ≈ 7 ms (≈ +15 %);
the cost shows only at the knee (500 flows/s offered: p50 19 → 62 ms, p99 169 → 254 ms). If the cost matters more than exact
shared limits for device endpoints, set `RATE_LIMIT_STORE=memory` and enforce the per-IP limits at the edge; the
account lockout stays shared regardless.

## Alternatives considered

| Option                                           | Why not (now)                                                                                                                                                                                  |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Redis for counters                               | New infrastructure, new failure mode and credentials for a control PostgreSQL can already carry at this scale; the backend interface keeps it a one-class change if the numbers ever demand it |
| Sync local counters to the database periodically | Cheaper per request but approximate and harder to reason about (overshoot = instances × sync interval); not appropriate for lockout                                                            |
| Edge/CDN only                                    | Right for volumetric abuse and still recommended, but the edge cannot see accounts: lockout must be ours                                                                                       |
| LOGGED table                                     | WAL and replication for data nobody wants after a crash                                                                                                                                        |

## Consequences

- An attacker no longer multiplies guesses by the number of instances; restarts no longer reset lockouts.
- Counter tables are bounded by maintenance; the in-memory structures are bounded as well.
  − One more statement per limited request when shared counters are on; row contention on a single hot client key
  (one IP hammering) serializes briefly on that row — which is the intended behaviour.
  − Windows are fixed windows (a burst straddling a boundary can reach 2 × the limit), as before.
  − A request that is rejected while the database is down is counted locally only until it recovers; multi-instance
  precision is lost during that period (visible via `rate_limit_fallback_total`).
  − Lockout can still be raced by parallel attempts that all pass the "is it locked?" check before any of them has
  failed (password hashing takes ~100 ms); the per-IP login limit bounds that parallelism. Pre-existing.
