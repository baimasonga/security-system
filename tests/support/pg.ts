import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll } from 'vitest';
import { applyAppGrants } from '../../services/platform-api/src/db/grants.ts';
import { MIGRATIONS_DIR, applyMigrations } from '../../services/platform-api/src/db/migrate.ts';
import type { PgPool } from '../../services/platform-api/src/db/pg.ts';

/** True when the suite should run against PostgreSQL instead of the in-memory adapters. */
export const pgTestEnabled = (): boolean => process.env['TRUST_TEST_PERSISTENCE'] === 'postgres';

/** True when the application must connect as the least-privilege role (the `db-approle` project). */
export const appRoleMode = (): boolean => process.env['TRUST_TEST_APP_ROLE'] === '1';
export const TEST_APP_ROLE = 'trust_test_app';

let admin: pg.Client | undefined;
const created: Array<{ schema: string; pool: pg.Pool }> = [];

function urlAs(role: string): string {
  const u = new URL(url());
  u.username = role;
  u.password = `test-only-${TEST_APP_ROLE}`;
  return u.toString();
}

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
    connectionString: appRoleMode() ? urlAs(TEST_APP_ROLE) : url(),
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
      if (appRoleMode()) {
        // The schema owner (a superuser here) migrates; the application role only gets the profile's grants.
        const exists = await mig.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [
          TEST_APP_ROLE,
        ]);
        if (!exists.rows.length)
          await mig
            .query(`CREATE ROLE ${TEST_APP_ROLE} LOGIN PASSWORD 'test-only-${TEST_APP_ROLE}'`)
            .catch(() => undefined);
        await mig.query(`ALTER ROLE ${TEST_APP_ROLE} PASSWORD 'test-only-${TEST_APP_ROLE}'`);
        await applyAppGrants(mig, { schema, role: TEST_APP_ROLE });
      }
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
