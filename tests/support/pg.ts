import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll } from 'vitest';
import { MIGRATIONS_DIR, applyMigrations } from '../../services/platform-api/src/db/migrate.ts';
import type { PgPool } from '../../services/platform-api/src/db/pg.ts';

/** True when the suite should run against PostgreSQL instead of the in-memory adapters. */
export const pgTestEnabled = (): boolean => process.env['TRUST_TEST_PERSISTENCE'] === 'postgres';

let admin: pg.Client | undefined;
const created: Array<{ schema: string; pool: pg.Pool }> = [];

function url(): string {
  const u = process.env['DATABASE_URL'];
  if (!u) throw new Error('DATABASE_URL is required for PostgreSQL tests (use `npm run test:db`)');
  return u;
}

/**
 * A pool whose connections live in a brand-new, fully migrated schema. Creation is lazy and the
 * first query/connect awaits it, so synchronous test setup code can use it unchanged.
 * Every schema is dropped when the test file finishes.
 */
export function createSchemaPool(): PgPool {
  const schema = `t_${randomBytes(6).toString('hex')}`;
  const pool = new pg.Pool({
    connectionString: url(),
    max: 6,
    idleTimeoutMillis: 300,
    options: `-c search_path=${schema}`,
  });
  created.push({ schema, pool });
  const ready = (async () => {
    admin ??= await (async () => {
      const c = new pg.Client({ connectionString: url() });
      await c.connect();
      return c;
    })();
    await admin.query(`CREATE SCHEMA ${schema}`);
    const mig = new pg.Client({ connectionString: url(), options: `-c search_path=${schema}` });
    await mig.connect();
    try {
      await applyMigrations(mig, MIGRATIONS_DIR);
    } finally {
      await mig.end();
    }
  })();
  return {
    async query(text, params) {
      await ready;
      return pool.query(text, params);
    },
    async connect() {
      await ready;
      return pool.connect();
    },
  } as PgPool;
}

afterAll(async () => {
  for (const { schema, pool } of created.splice(0)) {
    await pool.end().catch(() => undefined);
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
  }
  await admin?.end().catch(() => undefined);
  admin = undefined;
});
