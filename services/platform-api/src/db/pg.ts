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

/** SQLSTATEs that mean "nothing was applied, just run it again": serialization failure, deadlock. */
export const RETRYABLE = new Set(['40001', '40P01']);

export interface TransactionOptions {
  /** Total attempts including the first (default 4). */
  maxAttempts?: number;
  /** Test seam; default is a short jittered delay that grows with the attempt number. */
  sleep?: (ms: number) => Promise<void>;
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
  const client = await pool.connect();
  try {
    for (let attempt = 1; ; attempt++) {
      try {
        await client.query('BEGIN');
        const out = await fn(client);
        await client.query('COMMIT');
        return out;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => undefined);
        const code = pgErr(e).code;
        if (!code || !RETRYABLE.has(code) || attempt >= maxAttempts) throw e;
        await sleep(Math.floor(Math.random() * 20 * attempt) + 5 * attempt);
      }
    }
  } finally {
    client.release();
  }
}
