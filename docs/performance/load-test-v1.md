# Load and Soak Test — V1 Licensing Platform

Date: 2026-10-08 · Code under test: `claude/sleepy-carson-l0if1k` (before → after the changes listed in §4)
Related: [ADR-007](../adr/ADR-007-locking-and-retention-under-load.md) · [capacity & monitoring runbook](../runbooks/capacity-and-monitoring.md)

## 1. Summary

**What this is.** An open-loop load test of the real server process (separate from the load generator) against
real PostgreSQL 16 with `fsync` on, driving the real HTTP API with real Ed25519 device proofs: activation and
refresh flows, a hot-license case, an activation stampede, a 12-minute baseline soak and a 20-minute soak after
the fixes. **All numbers come from a shared 4-vCPU virtual machine** (server, PostgreSQL and generator competing
for the same cores, loopback networking), so absolute values are indicative; before/after comparisons on the
same machine and the _shapes_ of the curves are the reliable part.

**Headline results**

| Question                            | Answer (measured)                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Is it correct under load?           | Yes, in every run: **0 errors, 0 dropped, 0 licenses over their device limit, 0 deadlocks, audit chain verified** (130k events in 2.5 s), a 300-way stampede on a limit-5 license produced exactly 5 activations                                                                                                                                                                          |
| Single-instance capacity (loopback) | Refresh flow: clean to ~300 flows/s, saturates ~380–400. Activation flow: clean to ~200–300, saturates ~330. Knee is sharp (p99 ~50 ms → > 1 s within one step)                                                                                                                                                                                                                           |
| Is it stable over time?             | 120,000 flows / 20 min: p50 19.5 ms, p99 29.7 ms, **flat memory (141–144 MB), flat event-loop delay, flat per-minute p99** (27–32 ms, apart from one isolated 180 ms minute, LT-12)                                                                                                                                                                                                       |
| What limits it?                     | CPU (Node ~3 ms + PostgreSQL ~3.5 ms per refresh flow, ~22 database round trips at the time; 10 after ADR-009) on this box; and — **the important one** — the **single audit chain, whose ceiling depends on network round-trip time to PostgreSQL** (§3.7)                                                                                                                               |
| Did testing find real defects?      | **Yes — three in the code under test** (an unindexed per-request DELETE that would have collapsed the service after ~1 h of sustained load; a needless exclusive lock that serialized hot licenses; a pending `pg@9` incompatibility) **and two in my own work** (operator knobs that silently did nothing; a test flag that silently never failed). All fixed, with regression tests; §4 |
| What is _not_ shown?                | Throughput scaling across instances (no spare cores here), real network/disk latencies, runs longer than 20 min, failover, very large tables, real client behaviour (§5)                                                                                                                                                                                                                  |

## 2. Method

- **Open loop.** Operations are launched on a fixed schedule regardless of server speed and latency is measured from
  the _intended_ start time, so queueing is not hidden (no coordinated omission). A step is "saturated" when p99 > 2 s,
  error rate > 1 % or the generator had to drop operations because too many were in flight.
- **Flows measured.** _Refresh flow_ = `POST /v1/devices/challenges` + `POST /v1/licenses/refresh` (device-signed;
  one audited transaction). _Activation flow_ = challenge + `POST /v1/licenses/activate` (session + proof; Ed25519
  verify, lease signing, three audit events). Each flow is two HTTP requests.
- **Environment.** 4 vCPU Intel Xeon 2.1 GHz VM, 16 GB RAM. PostgreSQL 16.15, default `shared_buffers`, `fsync` on
  (`pg_test_fsync`: ≈ 4,300 fsync/s, 0.23 ms each). Node 22.22, pool 10, request logging at `info` to a discarded pipe,
  rate limits raised so limits are not what is measured. 2,000 seeded users/licenses unless stated.
- **Observability.** Server-side metrics (new `/v1/admin/metrics`), PostgreSQL stats (`pg_stat_activity`,
  `pg_stat_database` deadlocks), per-process CPU/RSS from `/proc`, generator CPU (to detect generator-bound runs).
- **Reproduce.** `npm run loadtest -- --scenario <name> [--rps a,b,c] [--seconds N] [--users N] [--instances N]
[--pool N] [--log warn] [--srvenv K=V,…] [--assert-clean] [--out file.json]`. Scenarios: `audit-micro`,
  `activate-ramp`, `refresh-ramp`, `hot-license`, `herd`, `soak`, `pool-sweep`, `latency-sweep`, `purge-micro`.
  CI runs a tiny `--assert-clean` smoke of the tool (it fails on any error or dropped operation — verified both ways).

## 3. Results

### 3.1 Audit chain in isolation (direct appends, loopback, `fsync` on)

| Concurrent appenders | events/s | p50 latency (ms) |
| -------------------- | -------- | ---------------- |
| 1                    | 996      | 0.9              |
| 4                    | 954      | 4.1              |
| 16                   | 869      | 17.8             |
| 64                   | 809      | 77.6             |

One global chain is serialized at commit: **~800–1,500 audited transactions/s regardless of concurrency**; extra
concurrency only adds latency. (Chain verification: 38k events in 0.5 s; 130k in 2.5 s.)

### 3.2 Activation flow ramp (single instance)

| Target flows/s | Before: achieved / p99 ms    | After: achieved / p99 ms  | Repeat of "after": achieved / p99 ms |
| -------------- | ---------------------------- | ------------------------- | ------------------------------------ |
| 100            | 99.7 / 32                    | 99.9 / 164 (outlier)      | 99.9 / 58                            |
| 200            | 199.8 / 57                   | 199.9 / 37                | 199.9 / 101                          |
| 300            | 278 / **1,512** (53 dropped) | 298 / 110                 | 294 / **1,041**                      |
| 400            | –                            | 334 / 1,646 (746 dropped) | 325 / 1,464 (814 dropped)            |

### 3.3 Refresh flow ramp (single instance)

| Target flows/s | Before: achieved / p99 ms     | After      | Repeat                   | Logging at `warn` |
| -------------- | ----------------------------- | ---------- | ------------------------ | ----------------- |
| 100            | 99.9 / 28                     | 99.9 / 30  | 99.9 / 31                | 99.9 / 28         |
| 200            | 199.9 / 28                    | 199.9 / 26 | 199.9 / 38               | 199.9 / 26        |
| 300            | 299 / 199                     | 300 / 98   | 300 / 64                 | 299 / 549         |
| 400            | 328 / **1,515** (748 dropped) | 394 / 627  | 378 / 1,217 (73 dropped) | 393 / 689         |

**Read the 300–400 rows as a band, not a point.** p99 at 300 flows/s across five runs of essentially the same
configuration ranged from **64 ms to 1,023 ms** (shared VM, CPU at 83–96 %). The honest statement is: _clean up to
about 200–250 flows/s, a knee between ~250 and ~400 where results are noisy, saturation beyond._ The improvements in
this table's "after" columns are **within that noise** and are not claimed; the changes are justified by §3.4, §3.9 and
§3.8, which isolate their effects. Request logging at `info` cost under ~3 % of CPU in the profile; `warn` showed no
reliable benefit.

### 3.4 One hot license vs the same load spread over 500 licenses (300 devices on the hot license)

| Target refreshes/s | Before: hot license achieved / p99 | Before: spread | After: hot license | After: spread |
| ------------------ | ---------------------------------- | -------------- | ------------------ | ------------- |
| 100                | 99.9 / 28                          | 99.9 / 27      | 99.9 / 26          | 99.9 / 77     |
| 200                | 199.9 / **123**                    | 199.9 / 25     | 199.9 / **25**     | 199.9 / 133   |
| 400                | 223 / 2,215                        | 338 / 1,454    | 356 / 1,582        | 368 / 1,250   |

Before the change, a single license was visibly worse than spread load (exclusive lock per refresh: 5× p99 at
200/s, 34 % lower ceiling, `pg_stat_activity` showed lock waiters). After switching refresh to a shared lock the
hot license is as good as spread load (the spread column shows ±100 ms noise of the same size as the old gap at lower
rates, so the claim is the _removal of the systematic gap_, backed by the lock-semantics tests in ADR-007).

### 3.5 Activation stampede

300 devices activating simultaneously on one license with limit 5: **exactly 5 succeeded, 295 were refused**, 0
deadlocks, 0 retries; wall time ≈ 2.0 s, p50 1.6 s (each decision serializes on the license lock, and each refusal
writes an audit record). Unchanged by the fixes.

### 3.6 Where the time goes; pool size; instances

- **CPU per refresh flow:** ≈ 3.2 ms Node, ≈ 3.5 ms PostgreSQL, ≈ 0.7 ms generator at ~300 flows/s. Server CPU
  profile (self time, busy portion): socket writes (`writev`) ≈ 21 %, pg driver ≈ 16 %, Ed25519 verify + sign ≈ 13 %,
  application code ≈ 10 %, pino ≈ 2 %, zod < 1 %. **The cost is dominated by the ~22 PostgreSQL round trips per flow**
  (the license context is loaded twice on the refresh path), not by validation, logging or crypto.
- **Pool size (fixed ~450 flows/s offered, 20 % activations):** pool 5 → 350/s, 10 → 359/s, 20 → 336/s, 40 → 323/s;
  mean audit-lock wait 2.7 → 11 → 38 → 100 ms. **Bigger pools made it worse**: more transactions hold a connection
  while queueing on the audit chain. Default 10 is right; 5–10 recommended.
- **Two instances:** correct (0 errors, 0 deadlocks, limits and single-use challenges held) but **no throughput gain
  on this machine** — total CPU (Node ×2 + PostgreSQL + generator ≈ 270 % of 4 vCPUs, hyperthreaded) was already
  exhausted, and audit-lock wait rose to 30–50 ms. This test **cannot** say how it scales on real hardware.
- **`fsync` off** improved latency at the knee (p99 104 ms vs 1,023 ms at 300 flows/s in the paired runs) but is not
  a production setting; disk is not the saturating resource at these rates (≈ 1,200 fsync/s of ≈ 4,300).

### 3.7 Network distance to PostgreSQL (injected via a delaying proxy; nominal RTT, timer-granularity limited)

| Nominal RTT API↔DB | Audit chain ceiling (events/s, concurrency 8)  | Refresh flow: p50 at 25/s | Refresh flow: sustainable rate |
| ------------------ | ---------------------------------------------- | ------------------------- | ------------------------------ |
| ≈ 0 (loopback)     | ~870 (≈1,040 after the round-trip merge below) | 57 ms                     | ≥ 200                          |
| ≈ 2 ms             | 110 → **157 after the merge**                  | 107 ms                    | ~90 (p99 1.1 s at 100)         |
| ≈ 4 ms             | 64                                             | 148 ms                    | ~50 (saturated at 100)         |
| ≈ 10 ms            | 29                                             | –                         | –                              |

The chain lock is held across four dependent round trips (take lock, read head, insert, commit), so the ceiling is
≈ 1 / (4·RTT + fsync). **This is the dominant production risk found**: at same-AZ latencies of 0.5–2 ms the ceiling
is a few hundred audited transactions per second, and at cross-AZ latencies about 100. Average fleet load is far below
that (1 M devices refreshing every 15 days ≈ 0.8 refreshes/s), but **bursts** (mass reconnect after an outage) can
reach it. One cheap mitigation is already in: the lock and the head read now travel in **one** round trip (separate
statements in one message, so each still gets a fresh snapshot — a single combined statement would read a snapshot
from _before_ the wait and fork the chain; a test with 240 concurrent appends over 4 connection pools fails if that
is done). That gave +43 % at 2 ms RTT and +19 % on loopback. The fundamental fix is a design change (§7).

### 3.8 Soak: 100 flows/s mixed (70 % refresh, 20 % validate, 10 % new activations)

|                                      | Baseline (12 min, unmodified retention)          | After fixes (20 min, 2 min retention)                              |
| ------------------------------------ | ------------------------------------------------ | ------------------------------------------------------------------ |
| Flows / errors / dropped             | 72,000 / 0 / 0                                   | 120,000 / 0 / 0                                                    |
| Latency p50 / p95 / p99 / p99.9 (ms) | 23.8 / 32.3 / 39.2 / 86.8                        | 19.5 / 24.4 / 29.7 / 91.0                                          |
| Per-minute p99 (ms)                  | 29 → 41 → 46 … 55 (**drifting up**)              | 27–32 in 19 of 20 minutes; **one minute (t = 900 s) at 180 ms**    |
| Server RSS (MB)                      | 147 → 147 (max 150)                              | 143 → 141 (max 144)                                                |
| Event-loop p99 (ms)                  | ≈ 11 (max 15)                                    | ≈ 11 (max 13)                                                      |
| `challenges` table at end            | 73,000 rows / 24 MB — **grows linearly forever** | 42,517 rows / 18.6 MB — **plateaued** (maintenance deleted 78,483) |
| Retries / exhausted / deadlocks      | 0 / 0 / 0                                        | 0 / 0 / 0                                                          |
| Audit chain verify                   | 82,759 events OK (1.4 s)                         | 131,149 events OK (2.5 s)                                          |
| Licenses over device limit           | 0                                                | 0                                                                  |

The after-soak retention was deliberately short (120 s) so that purging happens during the test; with the default
1 h retention the table's steady state is larger but equally bounded (≈ rate × (TTL + retention)).

### 3.9 The retention DELETE in isolation (500,000-row `challenges` table, nothing to delete)

|                                              | mean        | p99     |
| -------------------------------------------- | ----------- | ------- |
| With `expires_at` index (migration 0002)     | **0.24 ms** | 1.4 ms  |
| Without (the schema that was running before) | **52.5 ms** | 65.6 ms |

The old code ran this on _every challenge request_. With the table size it would reach at 100 requests/s under
the old 1 h retention (~390k rows) that is ≈ 40 ms of database CPU per request — **several cores' worth, i.e. the
service would have collapsed after roughly an hour of sustained load**, something neither the 12-minute baseline soak
(table only 67k rows → ~7 ms per request, visible only as the upward p99 drift in §3.8) nor any short ramp could reveal.

### 3.10 After ADR-008: partitioned audit chains (same box, 2 ms injected RTT, `audit-micro --oneway 1`)

Events/s for direct audited appends; each worker repeatedly appends one event. "system" = all events on one chain,
i.e. the old global-chain behaviour; the first run uses the same code path as before the change.

| Workload                            | 8 workers: events/s (p99) | 32 workers: events/s (p99) |
| ----------------------------------- | ------------------------- | -------------------------- |
| One chain (`system`, old behaviour) | 144 (875 ms)              | 147 (6,055 ms)             |
| 16 organizations, one chain each    | **584 (20 ms)**           | **1,680 (28 ms)**          |
| One hot organization, 1 shard       | 148 (802 ms)              | 150 (6,121 ms)             |
| One hot organization, 8 shards      | 502 (33 ms)               | 904 (209 ms)               |

Reading: with unrelated tenants the 2 ms-RTT ceiling moved from ≈ 147/s to ≈ 1,680/s (≈ 11×, now limited by CPU and
the pool rather than a lock), and p99 under 32-way contention fell from 6 s to 28 ms. A single hot tenant still
serializes at ≈ 150/s unless sharded (`AUDIT_CHAIN_SHARDS`), which bought ≈ 6× at 32 workers. Verification of the
final logs succeeded in every run (all chains and heads).

Regression check of the full-service scenarios after the change (same box; the load generator and a test run briefly
shared the CPU during the first step, so only the shape is claimed): activation ramp clean to 300 flows/s (p99 112 ms),
389 flows/s achieved at 400 offered; refresh ramp clean to 300 (p99 39 ms), 399 achieved at 400 offered; hot-license and
300-way stampede still correct (exactly 5 activations, 0 deadlocks); 5-minute soak at 100 flows/s: 30,000 flows, 0 errors,
p99 27.9 ms, flat per-minute p99 (27–29 ms) and flat memory. Not re-run: the 20-minute soak and multi-instance runs.

### 3.11 After ADR-009: fewer database round trips per flow

Statements sent to PostgreSQL per call chain (traced by `tests/integration/roundtrips.e2e.test.ts`, which now fails if a
flow exceeds its budget): **activation 23 → 14, refresh flow (challenge + refresh) 21 → 10, validation 11 → 5.**
Decisions, locks and audit events are unchanged ([ADR-009](../adr/ADR-009-fewer-database-round-trips.md)).

Refresh flow at injected round-trip times (`latency-sweep`, same box, same session, "before" = commit `1edd86b`
built in a separate worktree, "after" = this change; offered rate → achieved, p50 / p99 ms):

| RTT API↔DB | Offered | Before                              | After                         |
| ---------- | ------- | ----------------------------------- | ----------------------------- |
| ≈ 0        | 300/s   | 300 · 25 / 135                      | 300 · 16 / 54                 |
| ≈ 2 ms     | 25/s    | 25 · 102 / 111                      | 25 · 76 / 82                  |
| ≈ 2 ms     | 100/s   | 100 · 76 / 90                       | 100 · 47 / 59                 |
| ≈ 2 ms     | 200/s   | **142** · 2,789 / 3,775 (saturated) | **199** · 40 / 56 (clean)     |
| ≈ 2 ms     | 300/s   | –                                   | 282 · 436 / 943 (knee)        |
| ≈ 4 ms     | 100/s   | 92 · 815 / 1,620 (saturated)        | 100 · 62 / 71 (clean)         |
| ≈ 4 ms     | 200/s   | 90 · 5,240 / 6,063                  | 180 · 909 / 1,554 (saturated) |

Reading: the sustainable rate at a 2 ms round trip roughly **doubled (≈ 100 → ≈ 200+ flows/s)**, at 4 ms from < 100 to
≥ 100, and latency at light load fell by ≈ 25–40 % — in line with the ≈ 50 % cut in statements, since signing, proof
verification and the audit lock hold are unchanged. On loopback (CPU-bound) the ramps show the same shape with more
headroom: activation clean to 400/s (p99 281 ms; before: 389 achieved, p99 952 ms), refresh clean to 400/s (p99 64 ms;
before 314 ms) and 584/s achieved at 600 offered (before 502). Herd and hot-license scenarios were re-run and remain
correct (exactly 5 activations on the limit-5 license, 0 deadlocks). 5-minute soak at 100 flows/s: 30,000 flows, 0 errors,
p50 18.0 ms, p99 25.0 ms (before: 18.9 / 27.9), flat per-minute p99. Not re-run: the 20-minute soak, multi-instance runs.
Caveat: one shared 4-vCPU box; the load generator sat in the same CPU pool.

### 3.12 After ADR-011: shared rate-limit counters (`RATE_LIMIT_STORE=postgres` vs `memory`, same box, back to back)

Every limited request now costs one extra statement (the `commits` counter per flow rose from 5.3 to 8.1, confirming the
setting applied). Refresh ramp, loopback (offered → achieved · p50 / p99 ms):

| Offered | memory         | postgres       |
| ------- | -------------- | -------------- |
| 200/s   | 200 · 13 / 29  | 200 · 13 / 21  |
| 300/s   | 300 · 12 / 24  | 300 · 12 / 33  |
| 400/s   | 400 · 13 / 86  | 400 · 13 / 44  |
| 500/s   | 500 · 19 / 169 | 497 · 62 / 254 |

At a 2 ms round trip (refresh flow): 50/s p50 55 → 63 ms, 100/s 46 → 54 ms, 200/s 41 → 48 ms (≈ +15 %), no errors, no
saturation up to 200/s in either mode. Up to 400 flows/s on this box the shared counters are within noise; the knee
region (≈ 500/s) shows the cost. Lockout cost is one extra read per login and one atomic write per failure (logins are
dominated by password hashing). Not measured: multi-instance throughput, behaviour under a sustained database outage
(covered functionally by a test that drops the table: requests keep being served and limited locally).

### 3.13 After ADR-013: validation-state and subscription-plan fixes (2026-10-11)

A fresh local smoke comparison used an archived copy of baseline commit
`3ceb12f0975f253cfbf416cb86d0e02dc406e7ec` and the ADR-013 changes, with independent
empty databases, PostgreSQL 17.11, `fsync=on`, pool 10, and the API/load generator on
one cloud machine. The mixed workload chooses approximately 70% refresh, 20% validate,
10% activation randomly; these are short correctness checks, not capacity measurements.

| Workload                                       | Completed flows | Errors / drops | p50 / p99 (ms) |
| ---------------------------------------------- | --------------- | -------------- | -------------- |
| Baseline mixed, 80 users, 50/s, 15 s           | 750             | 0 / 0          | 26.60 / 33.81  |
| ADR-013 mixed, same settings                   | 750             | 0 / 0          | 26.25 / 32.54  |
| ADR-013 refresh, 80 users, 50/s, 4 s           | 200             | 0 / 0          | 26.78 / 30.93  |
| ADR-013 refresh, 80 users, 100/s, 4 s          | 400             | 0 / 0          | 15.78 / 20.55  |
| ADR-013 one hot license, 32 devices, 50/s, 4 s | 200             | 0 / 0          | 27.15 / 33.96  |
| ADR-013 spread, 40 users, 50/s, 4 s            | 200             | 0 / 0          | 26.75 / 32.83  |

Both mixed runs verified every audit chain and found **zero licenses over their device
limit**. The 50-device stampede against a limit-5 license produced **exactly 5 successes
and 45 `device_limit_reached` refusals**, zero deadlocks, and 282 ms wall time. Thus the
outcomes match the invariants in §3.4–3.5 and §3.11, while the round-trip regression test
still verifies ADR-009's 14 / 10 / 5 budgets. These results do not establish a speedup or
replace the longer soaks and production-hardware recommendations in §5 and §7.

Raw current-run JSON/logs were retained in `/workspace/.setup/security-load-results/`.
The tool's PostgreSQL CPU probe assumes an OS user named `postgres`; the workspace-local
cluster runs as `agent`, so its reported database CPU percentage is **unavailable**, not
zero. No conclusions use that field or the tool's hard-coded CPU-count metadata.

## 4. Findings and dispositions

| ID    | Severity      | Finding                                                                                                                                                                      | Evidence                                        | Status                                                                                                                                                                                         |
| ----- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LT-1  | **High**      | Retention `DELETE` on every challenge, with no index: cost grows with table size → latent total slowdown at sustained load                                                   | §3.9, §3.8 drift & growth                       | **Fixed**: removed from request path; background batched job; migration `0002` indexes; metrics; tests incl. query-plan test                                                                   |
| LT-2  | Medium        | Refresh took an exclusive license lock → hot licenses serialized                                                                                                             | §3.4                                            | **Fixed**: shared lock (`FOR SHARE`); semantics tested on PostgreSQL; service test asserts which lock each path takes                                                                          |
| LT-3  | Medium        | Concurrent statements issued on one transaction connection (works today, removed in `pg@9`)                                                                                  | driver deprecation warning during load          | **Fixed**: explicit per-connection serialization + test                                                                                                                                        |
| LT-4  | **High**      | Audit-chain throughput is bounded by ≈ 1/(4·RTT): hundreds/s at same-AZ latency, ~100/s cross-AZ; bursts can hit it                                                          | §3.1, §3.7                                      | **Fixed structurally (ADR-008)**: independent per-organization chains (optionally sharded); §3.10. Residual per-chain ceiling remains                                                          |
| LT-5  | Info          | Per-box capacity ≈ 200–300 flows/s, ~22 round trips and ~6.7 ms CPU per refresh flow                                                                                         | §3.3, §3.6                                      | **Fixed (ADR-009)**: 21 → 10 statements per refresh flow, 23 → 14 per activation; §3.11                                                                                                        |
| LT-6  | Info          | Pool > 10 reduces throughput (audit-lock convoy)                                                                                                                             | §3.6                                            | Documented; default kept                                                                                                                                                                       |
| LT-7  | Info          | Single-license stampede of 300 ≈ 2 s                                                                                                                                         | §3.5                                            | Documented (correct; clients should back off)                                                                                                                                                  |
| LT-8  | Medium (mine) | Operator knobs (`CHALLENGE_*`, `LEASE_*`) were silently not applied — a patch step matched nothing — so the first "after" soak ran with default retention and proved nothing | exact row counts (121,000 = all) vs expectation | **Fixed** + regression test that each knob changes behaviour; **process lesson**: patch scripts must assert their anchors, and a measured outcome must be checked against its _expected_ value |
| LT-9  | Medium (mine) | Load-tool `--assert-clean` never failed (same silent-no-op class) and the CLI mis-parsed valueless flags                                                                     | lint ("never reassigned"), then a negative test | **Fixed**; verified exit 0 on clean load and exit 1 on injected 429s                                                                                                                           |
| LT-10 | Info          | Row growth: audit ≈ 0.6 KB, lease ≈ 0.24 KB, challenge ≈ 0.35 KB per flow; audit is immutable and unbounded by design                                                        | §3.8 tables                                     | Documented in runbook; archival/partitioning plan recommended                                                                                                                                  |
| LT-11 | Open          | Scale-out throughput unverified. (Rate-limit and lockout counters now shared: ADR-011, §3.12)                                                                                | §3.6                                            | Needs real hardware; R-7 remains                                                                                                                                                               |
| LT-12 | Open          | One isolated 180 ms p99 minute during the 20-min soak (no errors/retries)                                                                                                    | §3.8                                            | Not investigated (suspect PostgreSQL checkpoint); capture `log_checkpoints` in the next run                                                                                                    |

## 5. Limits of this evidence

Single VM with shared cores; loopback only except §3.7 (approximated by a Node proxy with ~1 ms timer granularity);
one run per configuration for most rows (the noise band in §3.3 shows how much that matters); soak of 12–20 minutes
(slow leaks, bloat, autovacuum behaviour, WAL/checkpoint effects, and connection churn over hours are untested);
default PostgreSQL tuning; synthetic clients that always behave (no retry storms, no malformed traffic, no slow
clients); no failover, restart-under-load or network-partition testing; no multi-tenant skew beyond the hot-license
case; tables stayed small (≤ 130k audit rows) — the audit index and verification cost at 10⁸ rows are extrapolation.

## 6. Notes on specific numbers

- Step latencies at 25–50 flows/s (≈ 55 ms → 30 ms p50) are _higher_ than at 100–200 flows/s (≈ 20 → 15 ms): warm-up
  (JIT, connection establishment) and PostgreSQL group commit benefit from concurrency. Quote the 100–200 rows as
  steady-state.
- `srvCPU` is percent of one core (a single Node thread cannot exceed ~100 %).
- The one 180 ms soak minute (LT-12) is included in all summary statistics above.

## 7. Recommendations (ordered by evidence)

1. **Audit chain ceiling (LT-4): done (ADR-008).** Remaining: set `AUDIT_CHAIN_SHARDS` only for tenants that show
   `audit_lock_wait_ms` growth; publish the verify `anchor` externally (R-13); re-run `latency-sweep` on real hardware.
2. **Round trips per flow: done (ADR-009).** Remaining statements are mostly structural (BEGIN, audit head lock, audit
   insert, COMMIT, challenge consume). Next candidates if needed: issue the challenge without a database write
   (stateless signed challenge — needs a new ADR, it changes replay protection) and pipelining `BEGIN` with the first read.
3. **Validate scale-out on real hardware** (≥ 8 cores, separate database host): `--instances 2,4` with `latency-sweep`;
   (rate limiting and lockout are already shared, ADR-011).
4. **Long soak (≥ 24 h) with `log_checkpoints`, autovacuum stats and table/index bloat sampling**, including a rolling
   restart and a PostgreSQL restart under load; investigate LT-12.
5. **Client guidance:** SDKs should add jittered exponential backoff on `device_limit_reached`/`rate_limited`/5xx
   (stampede on one license ≈ 2 s per 300 attempts) and spread lease refreshes (`refresh_after` jitter) to avoid
   synchronized reconnect storms after outages.
6. **Capacity planning for storage:** audit growth is the only unbounded table; plan archival or partitioning by time
   once real volumes are known (1 M devices ≈ 14 GB/year of audit at the modelled refresh rate).

### 3.14 Portal and identity-recovery transaction check

Compared archived revision `31576fa` with the browser/recovery working tree on the same cloud host using separate fresh databases for each scenario, `--users 40 --rps 20 --seconds 4 --assert-clean`. All four runs completed 80/80 flows with zero errors, drops, deadlocks or exhausted retries; each measured flow produced its expected audit append. This is a low-load regression smoke, not capacity or statistically significant speed evidence.

| Scenario | Baseline p50/p99 (ms) | Recovery p50/p99 (ms) |
| -------- | --------------------- | --------------------- |
| Activate | 62.67 / 87.97         | 61.56 / 82.53         |
| Refresh  | 59.73 / 67.46         | 59.22 / 61.24         |

Login now takes a user-row lock and rechecks the verified password hash before session creation to serialize with recovery; the extra query is on login, not license validation/refresh. PostgreSQL CPU output is unavailable because the probe expects an OS `postgres` user; emitted zero must not be interpreted as measured CPU. Final table statistics are PostgreSQL estimates, not exact business-record counts. Results are saved under `/workspace/.setup/feature-load-{base,new}-{activate,refresh}.json`; regression assertions check completed flow and audit counters explicitly.

### 3.15 Authenticator MFA regression smoke (2026-10-12)

Baseline: `35c4c22`; MFA working tree adds migration 0007, factor consumption under the user lock, and session revocation on factor changes. Fresh independent local PostgreSQL 17 databases; fsync on; 40 seeded users, 20 requests/second for four seconds per activation/refresh scenario. Run sequentially after application/database tests finished; an earlier overlapping run is not used for latency comparison.

| Revision / scenario | p50 ms | p99 ms | Successful / launched | Drops / errors |
| ------------------- | ------ | ------ | --------------------- | -------------- |
| base activate       | 62.33  | 94.74  | 80 / 80               | 0              |
| base refresh        | 60.74  | 76.58  | 80 / 80               | 0              |
| new activate        | 62.67  | 96.16  | 80 / 80               | 0              |
| new refresh         | 59.89  | 81.38  | 80 / 80               | 0              |

All four runs: 80 completed, 80 expected audit appends, zero deadlocks, transaction exhaustion or errors. This is a short regression smoke, not a capacity or performance improvement claim, and does not measure MFA login throughput. Authenticator and recovery-code concurrency is separately verified through behavioral tests on both PostgreSQL roles. PostgreSQL CPU reported by this local harness is unavailable; final table row statistics are estimates and are not used as business outcome counts. Local artifacts: `/workspace/.setup/mfa-load-{base,new}-{activate,refresh}.json`.

### 3.16 Audit head lock-order correction (2026-10-12)

Baseline `ce22b18` versus per-chain ordered acquisition. Fresh independent PostgreSQL 17 databases, fsync on, no concurrent test suites. Each soak uses 80 users, 50 requests/second, 15 seconds: 750 launched/completed/successful, zero drops/errors, zero retries/exhaustion/deadlocks. Both audit chains verify; verified event count equals the exact audit row invariant, consumed challenges equal 830 (80 initial activations plus 750 workload requests), and no license exceeds its device limit. Mixed-workload audit and lease counts vary with the sampled operations and are not compared as fixed totals. Baseline p50/p99 27.01/35.48 ms; correction 26.82/33.34 ms.

Hot-license refresh smoke: 32 devices, 50 requests/second, four seconds each on one license and spread across licenses. Both: 200 launched/completed/successful, 200 expected audit appends, zero drops/errors/deadlocks/retry exhaustion. p50/p99: one license 27.49/31.93 ms; spread 27.04/29.90 ms. These short runs establish regression behavior, not capacity or a speedup. Deterministic creation-race and concurrent multi-chain tests cover the corrected lock ordering directly. Local artifacts: `/workspace/.setup/audit-order-{base_soak,new_soak,new_hot}.json`.

### 3.17 Monthly quotas and load-server readiness (2026-10-12)

Baseline `49d7655` versus quota release. Fresh independent PostgreSQL 17 databases, fsync verified on, 40 users, 20 requests/second for four seconds per activation/refresh scenario. Sequential isolated comparison after all application/database tests finished. An earlier overlapping run exposed the tool's occupied-port readiness bug; those measurements are not used here. The tool now requires its own child's private readiness acknowledgement before probing health; a regression test fails against the previous implementation.

| Revision / scenario | p50 ms | p99 ms | Successful / launched |
| ------------------- | ------ | ------ | --------------------- |
| base activate       | 60.95  | 79.4   | 80 / 80               |
| base refresh        | 59.13  | 67.07  | 80 / 80               |
| new activate        | 60.74  | 75.23  | 80 / 80               |
| new refresh         | 58.72  | 71.9   | 80 / 80               |

Every comparison run: 80 completed, 80 expected audit appends, zero drops/errors/deadlocks/exhausted transactions. This short smoke does not establish capacity or a speedup. PostgreSQL CPU is unavailable to the local harness and is not interpreted as zero load.

Quota contention after the comparison: one shared license with allowance 20; 50 requests/second for four seconds; each operation is attempted twice. All 200 requests complete: 40 HTTP successes return 20 unique receipts, and 160 expected quota refusals occur. Exact ledger usage is 20, remaining is zero, exactly 20 audit appends occur and the full audit chain verifies. Zero drops, unexpected errors, deadlocks or exhausted transactions. p50/p99 24.39/33 ms. A lighter CI smoke at 20 requests/second separately checks 40 operation IDs, 20 receipts, 40 successes and 40 quota refusals. PostgreSQL mutation testing catches replacing the exclusive license lock with a shared lock, proving the concurrent-budget regression is sensitive to that control.

Artifacts: `/workspace/.setup/quota-load-{base,new}-{activate,refresh}.json` and `/workspace/.setup/quota-final-{light,stress}.json`.
