# ADR-006 — Audit is atomic with the change; transactions are retried on deadlock

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (audit integrity, availability under contention)
- Closes: threat-model risks **R-10** and **R-14**. Builds on [ADR-005](ADR-005-postgresql-adapters.md).

## Context

1. Audit entries were written _after_ the business transaction committed. A crash or an
   audit-store failure in between produced an **unaudited state change** (or, for multi-step
   operations such as registration, a half-applied one). For a platform whose value is
   accountability, "changed but not recorded" must be impossible, not merely unlikely.
2. Transactions use READ COMMITTED with explicit row locks. Under contention PostgreSQL may abort
   one transaction with a deadlock (`40P01`) or serialization failure (`40001`). That surfaced as an
   HTTP 500 although re-running would succeed.

## Decision

### Atomic audit

- `store.transaction(fn)` hands `fn` a transaction object that carries an **`AuditWriter`**
  (`tx.audit.append(event)`). Events are _buffered_ (`AuditBuffer`) and written by the adapter
  **inside the same unit of work**, as the last statement before COMMIT:
  - PostgreSQL: `appendAuditInTx` takes the chain advisory lock, extends the hash chain and inserts
    the rows in the caller's transaction. Taking the lock last keeps it held only briefly and avoids
    lock-ordering problems with row locks.
  - In-memory: the buffer is flushed to the audit log with a single all-or-nothing `appendMany`; any
    failure restores the state snapshot.
- **Fail closed:** if the audit write fails, the transaction rolls back and the operation fails.
  There is no code path that changes licensing/identity state without its audit record.
- `AuditLog.appendMany` is part of the port: a batch is contiguous in the chain and all-or-nothing
  (found and fixed by the contract suite: the in-memory log had written part of a bad batch).
- Converted: every operator mutation, trial start, activation (device registration + activation +
  lease record + 3 audit events), refresh, both deactivation paths, registration (now also atomic
  across user + personal org + membership), login, logout, org creation, member add, operator
  bootstrap/revoke.
- **Not** in the transaction, deliberately: audit of _refusals_ (rejected activation, replay, canary
  hits, failed login, access denied). They have no state change to be consistent with and must
  record even though the operation failed; they use the standalone `AuditLog.append` (itself atomic).
  Telemetry stays best-effort and outside.

### Retry

- `withTransaction` re-runs the **whole attempt** (fresh BEGIN, fresh audit buffer) after `40P01` or
  `40001`, up to 4 attempts, with a short growing jittered delay, on the same connection. Every other
  error (domain errors, constraint violations, unknown errors) rolls back and is rethrown at once;
  exhausted retries rethrow the original error.
- **Re-runnable callbacks are a contract** (documented on the port): callbacks must derive state
  from reads inside the transaction and perform no irreversible side effects. The two licensing
  callbacks that mutate captured variables (`startTrial`, `activate`) are idempotent per attempt.
- **One lock order everywhere: license → activation.** `refresh` previously locked the activation
  only; it now locks the license first and **re-evaluates access under the lock**, which also closes
  a small time-of-check/time-of-use window (a suspension committed between device authentication and
  lease issuance used to still yield one lease).

## Consequences

- A state change and its audit record are one atomic fact; verified by contract tests on both
  adapters, an audit-trigger-failure test on PostgreSQL, and mutation checks.
- A genuine PostgreSQL deadlock (opposite lock order) is retried and both transactions succeed.
  − Audited transactions serialize briefly on the chain lock at commit. Throughput of audited
  writes is bounded by the append rate of one chain (acceptable for a control plane; revisit with
  load tests, e.g. batching or per-tenant chains).
  − Retried work is repeated work; callbacks must stay cheap and side-effect-free (signing is local).
  − A database superuser can still rewrite history (R-13): atomicity ≠ immutability.
