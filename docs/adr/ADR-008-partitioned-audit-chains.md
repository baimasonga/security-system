# ADR-008 — Partitioned audit chains (per organization, optionally sharded)

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (audit integrity model, availability)
- Closes the structural part of threat-model risk **R-15**; evidence in the
  [load-test report](../performance/load-test-v1.md) (§3.1, §3.7, §7). Supersedes the "one global chain" design of ADR-006/-005.

## Context

Every audited change appends to **one global hash chain**, serialized by an advisory lock that is held across the
read of the head, the insert and the **commit**. Load testing showed the ceiling is therefore ≈ 1 / (3–4·RTT + fsync)
audited transactions per second for the _whole platform_: ~870/s on loopback, ~157/s at a 2 ms round trip to
PostgreSQL, ~64/s at 4 ms. Unrelated tenants queue behind each other; a reconnect storm in one organization slows
every other organization's activations and refreshes.

What the chain must keep providing: (1) tamper evidence for any edit/insert/delete inside a history, (2) atomicity with
the business change (ADR-006), (3) cheap verification, (4) a way to detect truncation of the tail.
What it does **not** need: a single total order across unrelated tenants — nothing in the product consumes one.

## Decision

1. **Partition the log into independent hash chains.** An event belongs to exactly one chain, chosen deterministically
   from the event itself:
   - events with an `orgId` → `org:<url-encoded orgId>`; with `AUDIT_CHAIN_SHARDS = N > 1` →
     `org:<id>#<k>`, `k = uint32(sha256(target.id ?? actor.id ?? "")[0..4]) mod N` (a device's events always land in the
     same shard; a hot tenant gets up to N-way parallelism; default N = 1);
   - events without an organization (logins, failed logins, operator bootstrap, key lifecycle, unknown-key
     rejections…) → `system`;
   - events written before this change → `legacy` (kept verbatim; still verifies; never extended).
2. **Each chain has its own `seq` (from 1) and `prev_hash`, and the hash covers the chain id**
   (`chain` is part of the hashed object for all new events), so an event cannot be moved or replayed into another
   chain without detection. Legacy events hash exactly as before.
3. **A head row per chain** (`audit_chains(chain_id, head_seq, head_hash)`) is the lock _and_ the head:
   `SELECT … FOR UPDATE` on the head rows of the chains an append touches (sorted by chain id, to keep lock order
   deterministic) returns the current heads in the **same round trip** that takes the lock; one statement then inserts
   all events (`unnest` arrays) and updates the heads; then commit. Lock hold time is unchanged (≈ 3 round trips) but
   **only appenders to the same chain contend**. New chains are created with `INSERT … ON CONFLICT DO NOTHING`.
   The advisory lock and the "multi-statement message" trick are no longer needed.
4. **Verification covers every chain and the heads**: each chain is replayed with the shared `ChainVerifier`
   (sequence, `prev_hash`, content hash, chain id), then its last event must equal the stored head, every chain with
   events must have a head, and a head with `head_seq > 0` must have events. `verifyChain({ orgId })` verifies only
   that organization's chains (cheap, tenant-scoped); the unscoped call also returns an **anchor** =
   `sha256(canonical JSON of the sorted [chain, head_seq, head_hash] list)` — one value an operator can publish to
   an external append-only store to witness the whole log (mitigation for R-13; publishing it is an operational step).
5. **Database hardening for the heads**: `audit_chains` rejects DELETE/TRUNCATE, rejects changing `chain_id`, and
   rejects any update that lowers `head_seq` (defense in depth; a superuser can still disable triggers — R-13).
6. **Listing keeps a global display order** (`gseq` identity column, insertion order); it is not a trust claim.
7. **Atomicity is unchanged**: events are still buffered in the store transaction and written in the same database
   transaction as the change; a batch spanning several chains is all-or-nothing.

## Alternatives considered

| Option                                                       | Why not (now)                                                                                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Keep one chain, shave round trips (done earlier: +19…43 %)   | Still a single global bottleneck: ≈ 1/(3·RTT) for the whole platform                                                                       |
| Database-side `append_audit()` computing the hash in SQL     | One fewer round trip inside the lock but reimplements canonical JSON in SQL (fragile), and still global                                    |
| Asynchronous "sealer" assigning chain positions after commit | Removes audit from the hot path, but unsealed events are not tamper-evident until sealed and ordering/atomicity reasoning gets much harder |
| Optimistic concurrency (compare-and-swap on the head)        | Fewer round trips uncontended, but retries amplify under exactly the hot-tenant contention we need to handle                               |
| Per-device chains                                            | Maximum parallelism but verification/anchoring cost scales with devices; org(+shard) chains were enough in tests                           |

## Consequences

- Audited-write throughput scales with the number of active tenants instead of being capped globally; a tenant's
  burst no longer degrades others. Sharding adds capacity for a single hot tenant.
- Tenant-scoped verification becomes possible and cheap; the anchor gives a single value to witness externally.
  − **No global total order across chains.** Cross-tenant forensics order by `occurred_at`/`gseq` (display), not by a
  cryptographic sequence. Within a chain order is cryptographic.
  − A whole chain can be removed together with its head row by an attacker who can disable triggers; only an external
  anchor detects that (same class as R-13, no worse than tail truncation of the old single chain).
  − More rows (one head per active chain) and more chains to verify; sharding multiplies chains per organization (default 1).
  − Changing `AUDIT_CHAIN_SHARDS` later is safe (existing chains stay valid; new events use the new mapping) but it
  re-routes a device's _future_ events to a different shard.
  − The `system` chain remains a single serialization point for org-less events (mostly human logins, which are
  CPU-bound by password hashing long before the chain matters).

## Migration

`0003_partitioned_audit.sql`: adds `chain_id` (existing rows → `legacy`) and `gseq`, replaces the primary key
`(seq)` with `(chain_id, seq)`, creates `audit_chains` and seeds the `legacy` head from the last existing event.
Tested by applying 0001+0002, writing legacy-hashed events, then applying 0003 and verifying that the legacy chain
still verifies, new events go to new chains, and immutability still holds.

## Lock ordering correction (2026-10-12)

Concurrent CI batches exposed a creation race: locking every existing head first, then creating missing heads, can hold a later chain while waiting for an earlier chain's uncommitted creator. The acquisition order now covers both lookup and creation in one binary-sorted per-chain loop. Each head is fully locked or created before moving to the next. Single-chain appends retain one lookup; multi-chain batches use one lookup per head. No database locale sort participates. A deterministic PostgreSQL regression holds an earlier uncommitted head and verifies the waiting appender has not acquired the later head; it fails against the previous implementation. Retries remain a safety net, not the lock-order strategy.
