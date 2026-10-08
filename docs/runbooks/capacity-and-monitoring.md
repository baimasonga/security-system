# Capacity, Monitoring and Tuning (V1)

Evidence: [load-test report](../performance/load-test-v1.md). All numbers below were measured on a **shared
4-vCPU sandbox** (server, PostgreSQL and load generator on the same machine); treat them as relative, and re-measure
on production-like hardware before sizing. Decisions: [ADR-007](../adr/ADR-007-locking-and-retention-under-load.md).

## 1. What to watch (operator endpoint `GET /v1/admin/metrics`, add `?format=prometheus` for scraping)

| Signal                 | Metric                                    | Healthy                       | Alert when        | Likely cause / first action                                                                                                                                                                     |
| ---------------------- | ----------------------------------------- | ----------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Retries exhausted      | `db_tx_total{outcome="exhausted"}`        | 0                             | any increase      | Sustained lock contention. Inspect `db_tx_retries_total{sqlstate}`; look for one hot license                                                                                                    |
| Deadlock retries       | `db_tx_retries_total{sqlstate="40P01"}`   | ~0                            | sustained > 1/min | A code path violates lock order (license → activation)                                                                                                                                          |
| Pool pressure          | `db_pool_waiting`                         | 0                             | > 0 for 1 min     | Saturation. **Do not just raise `DB_POOL_MAX`** (measured: bigger pools made it worse) — see §3                                                                                                 |
| Audit chain contention | `audit_lock_wait_ms` (p99)                | < 5 ms                        | > 50 ms           | Audited-write rate near ONE chain's ceiling (≈ 1/(3·RTT) per organization chain; unrelated organizations no longer share it — ADR-008). If one tenant is hot, raise `AUDIT_CHAIN_SHARDS` (1–64) |
| Event loop             | `process_event_loop_delay_p99_ms`         | ≈ 10–12 ms (timer resolution) | > 100 ms          | CPU saturation of the Node thread; scale out or cut work per request                                                                                                                            |
| Request latency        | `http_request_duration_ms{route=…}` p99   | < 100 ms at < 60% capacity    | p99 > 500 ms      | Saturation (the knee is sharp: ~50 ms → > 1 s within one load step)                                                                                                                             |
| Retention health       | `maintenance_runs_total{outcome="error"}` | 0                             | any               | Tables will grow unbounded (§4). Check DB connectivity / locks                                                                                                                                  |
| Audit integrity        | `GET /v1/admin/audit/verify`              | `ok: true`                    | `ok: false`       | Incident-response §D. Verification took ~2 s for 130k events here — schedule it, don't run per request                                                                                          |
| Process                | `process_rss_bytes`                       | flat (≈ 150 MB observed)      | monotonic growth  | Leak. Compare against the soak baseline                                                                                                                                                         |

## 2. Measured capacity (single instance, 10-connection pool, `fsync` on)

- **Refresh flow** (challenge + refresh, 2 requests, 1 audited transaction): clean to ~300 flows/s; saturates ~380–400.
- **Activation flow** (challenge + activate, Ed25519 verify + lease signing, 1 transaction with 3 audit events): clean to
  ~200–300 flows/s; saturates ~330.
- **Audit append ceiling:** ≈ 800–1,500 events/s on loopback (one chain, serialized at commit). Throughput does **not**
  improve with concurrency; latency grows linearly with it. **It falls with round-trip time to PostgreSQL**
  (≈ 1/(3–4·RTT)): measured ≈ 157 events/s at a nominal 2 ms RTT, ≈ 64 at 4 ms, ≈ 29 at 10 ms. Co-locate the API with the
  database (same AZ, ideally same host group) and re-run `latency-sweep` for your topology before sizing.
- **One license, 300 devices activating at once, limit 5:** exactly 5 succeed, the other 295 are refused; takes ~2 s
  because each decision serializes on the license lock (no deadlocks, no retries needed).
- **Per-flow cost:** ≈ 3 ms of Node CPU and ≈ 3.5 ms of PostgreSQL CPU, ≈ 22 database round trips per refresh flow.
- Realistic fleets are far below this: at one refresh per device per 15 days, 300 flows/s is hundreds of millions of
  devices. The relevant risks are **bursts** (post-outage reconnect storms, a single huge license) and **table growth**,
  not average rate.

## 3. Tuning knobs (environment variables, validated at start-up)

| Variable                                              | Default                                  | Guidance                                                                                                                          |
| ----------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `DB_POOL_MAX`                                         | 10                                       | **5–10 per instance is best** on a 4-core host; 20–40 measurably increased audit-lock waits (2.7 → 100 ms) and lowered throughput |
| `RATE_LIMIT_GLOBAL/LOGIN/REGISTER/CHALLENGE/ACTIVATE` | 300 / 10 / 5 / 60 / 20 per minute per IP | Per **process** memory (R-7). Raise behind a CDN/NAT with many devices per IP, and enforce real limits at the edge                |
| `LOG_LEVEL`                                           | info                                     | `warn` had no clear benefit in measurements (logging was < 3% of CPU); keep `info` for the audit trail of requests                |
| `CHALLENGE_TTL_SECONDS`                               | 300                                      | Lifetime of a device challenge (10–3600)                                                                                          |
| `CHALLENGE_RETENTION_SECONDS`                         | 3600                                     | How long spent/expired challenges are kept before maintenance deletes them                                                        |
| `LEASE_RETENTION_SECONDS`                             | 90 days                                  | How long _expired_ lease records are kept (forensics; audit log keeps `lease.issued` forever)                                     |
| `MAINTENANCE_INTERVAL_SECONDS`                        | 60                                       | Retention job cadence; each pass is bounded (20 × 5,000 rows)                                                                     |

Scaling out: run several instances against the same PostgreSQL (correctness was verified with two: no errors, no
deadlocks, device limits and single-use challenges held). **Not yet validated:** throughput scaling (the test machine
had no spare cores) — and rate-limit / login-lockout counters are per instance (R-7).

## 4. Storage growth (measured)

| Table                    | Rows per…                                                       | Size per row (incl. indexes) | Retention                                                       |
| ------------------------ | --------------------------------------------------------------- | ---------------------------- | --------------------------------------------------------------- |
| `audit_events`           | ~1 per refresh, 3 per activation, 1 per rejection/deactivation… | ≈ 0.6 KB                     | **Immutable, unbounded by design** — plan archival/partitioning |
| `leases`                 | 1 per lease issued                                              | ≈ 0.24 KB                    | expired + `LEASE_RETENTION_SECONDS`                             |
| `challenges`             | 1 per device call                                               | ≈ 0.35 KB                    | expired + `CHALLENGE_RETENTION_SECONDS`                         |
| `activations`, `devices` | per device                                                      | ≈ 0.7 KB, 0.6 KB             | not purged                                                      |

Example: 1 M devices refreshing every 15 days ≈ 67k refreshes/day ≈ 40 MB/day of audit growth ≈ 14 GB/year.
Steady-state `challenges` size ≈ `rate × (TTL + retention)`; `leases` ≈ `rate × (lease TTL + retention)`.

## 5. Procedures

- **Latency suddenly high, CPU on the API low:** check `db_pool_waiting` and `audit_lock_wait_ms`; look in PostgreSQL for
  long transactions holding row locks (`pg_stat_activity`, `wait_event_type = 'Lock'`).
- **Hot license complaints (one org slow):** expect activation stampedes to block that license for seconds; refreshes
  of other licenses are unaffected. If persistent, check for a retry loop in a client (activation retried without backoff).
- **Re-run the load test** after any change to locking, transactions, the audit path or schema:
  `npm run loadtest -- --scenario refresh-ramp --rps 100,200,300` (see the report for all scenarios).
