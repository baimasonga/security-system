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

/** Run `fn` in a transaction on a dedicated connection (READ COMMITTED + explicit row locks). */
export async function withTransaction<T>(
  pool: PgPool,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    client.release();
  }
}
