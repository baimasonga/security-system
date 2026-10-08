import type { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';

/** What the adapters need from a pool; lets tests inject a schema-scoped pool. */
export interface PgPool {
  query<R extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: unknown[],
  ): Promise<QueryResult<R>>;
  connect(): Promise<PoolClient>;
}
export type Queryable = Pick<PgPool, 'query'>;
export type { Pool, PoolClient };

export interface PgError {
  code?: string;
  constraint?: string;
}
export const pgErr = (e: unknown): PgError => (typeof e === 'object' && e ? (e as PgError) : {});

export const UNIQUE_VIOLATION = '23505';
export const FK_VIOLATION = '23503';

/**
 * A single PostgreSQL connection runs one statement at a time. Service code is free to `Promise.all`
 * several repository reads inside a transaction (they all share the transaction's connection); this
 * wrapper turns that into an explicit queue instead of relying on the driver's deprecated implicit
 * queueing (removed in pg@9). Order of issue is preserved; a failed query does not poison the queue.
 */
export function serialized(q: Queryable): Queryable {
  let tail: Promise<unknown> = Promise.resolve();
  return {
    query: ((text: string, params?: unknown[]) => {
      const run = () => q.query(text, params);
      const p = tail.then(run, run);
      tail = p.catch(() => undefined);
      return p;
    }) as Queryable['query'],
  };
}

/** SQLSTATEs that mean "nothing was applied, just run it again": serialization failure, deadlock. */
export const RETRYABLE = new Set(['40001', '40P01']);

export interface TransactionOptions {
  /** Total attempts including the first (default 4). */
  maxAttempts?: number;
  /** Test seam; default is a short jittered delay that grows with the attempt number. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Process-wide observer for transaction behaviour (retries, durations, audit-lock waits). It carries
 * only counts, durations and SQLSTATE codes — nothing about the data being written.
 */
export interface TransactionObserver {
  onTransaction?(e: {
    outcome: 'ok' | 'error' | 'exhausted';
    attempts: number;
    durationMs: number;
  }): void;
  onRetry?(e: { code: string; attempt: number }): void;
  onAuditLockWait?(ms: number): void;
}
export const observer: TransactionObserver = {};
export function setTransactionObserver(o: TransactionObserver): void {
  observer.onTransaction = o.onTransaction;
  observer.onRetry = o.onRetry;
  observer.onAuditLockWait = o.onAuditLockWait;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Run `fn` in a transaction on a dedicated connection (READ COMMITTED + explicit row locks).
 *
 * Deadlocks (40P01) and serialization failures (40001) roll the attempt back and re-run `fn` on the
 * same connection, up to `maxAttempts`. Anything else — including domain errors thrown by `fn` and
 * constraint violations — is rolled back and rethrown immediately.
 *
 * CONTRACT: `fn` must be safe to run more than once. It may be re-executed from the start, so it must
 * not perform irreversible side effects (network calls, external writes) and must derive its state
 * from reads inside the transaction.
 */
export async function withTransaction<T>(
  pool: PgPool,
  fn: (client: PoolClient) => Promise<T>,
  opts: TransactionOptions = {},
): Promise<T> {
  const maxAttempts = opts.maxAttempts ?? 4;
  const sleep = opts.sleep ?? defaultSleep;
  const started = performance.now();
  const client = await pool.connect();
  let attempts = 0;
  try {
    for (let attempt = 1; ; attempt++) {
      attempts = attempt;
      try {
        await client.query('BEGIN');
        const out = await fn(client);
        await client.query('COMMIT');
        observer.onTransaction?.({
          outcome: 'ok',
          attempts,
          durationMs: performance.now() - started,
        });
        return out;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => undefined);
        const code = pgErr(e).code;
        if (!code || !RETRYABLE.has(code)) {
          observer.onTransaction?.({
            outcome: 'error',
            attempts,
            durationMs: performance.now() - started,
          });
          throw e;
        }
        if (attempt >= maxAttempts) {
          observer.onTransaction?.({
            outcome: 'exhausted',
            attempts,
            durationMs: performance.now() - started,
          });
          throw e;
        }
        observer.onRetry?.({ code, attempt });
        await sleep(Math.floor(Math.random() * 20 * attempt) + 5 * attempt);
      }
    }
  } finally {
    client.release();
  }
}
