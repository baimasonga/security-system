// OPS-002 integrity load check: real loopback HTTP + isolated PostgreSQL schema, fsync on.
// DATABASE_URL=<disposable local database> node tools/loadtest/operations.ts
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import pg from 'pg';
import { buildApp } from '../../services/platform-api/src/app.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
import { loadConfig } from '../../services/platform-api/src/config.ts';
import { applyMigrations, MIGRATIONS_DIR } from '../../services/platform-api/src/db/migrate.ts';
const databaseUrl = process.env['DATABASE_URL'];
if (!databaseUrl) throw new Error('DATABASE_URL required: use a disposable local database');
const schema = 'ops_load_' + randomBytes(6).toString('hex');
const admin = new pg.Client({ connectionString: databaseUrl });
await admin.connect();
const pool = new pg.Pool({
  connectionString: databaseUrl,
  options: `-c search_path=${schema}`,
  max: 16,
});
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
try {
  assert.equal(
    (await admin.query('SHOW fsync')).rows[0]?.fsync,
    'on',
    'load evidence requires fsync on',
  );
  await admin.query(`CREATE SCHEMA ${schema}`);
  const migrator = await pool.connect();
  try {
    await applyMigrations(migrator, MIGRATIONS_DIR);
  } finally {
    migrator.release();
  }
  const c = await createContainer(
    {
      ...loadConfig({ NODE_ENV: 'test' }),
      operationsInventoryEnabled: true,
      scrypt: { N: 1024, r: 8, p: 1 },
      rateLimits: {
        global: 100000,
        login: 100000,
        register: 100000,
        challenge: 100000,
        activate: 100000,
        sharing: 100000,
      },
    },
    { pool },
  );
  app = await buildApp(c);
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const account = await c.auth.register({
    email: 'load@example.test',
    password: 'load-test-password-long',
  });
  const token = (
    await c.auth.login({ email: 'load@example.test', password: 'load-test-password-long' })
  ).token;
  const base = `/v1/organizations/${account.personalOrg.id}/operations/applications`;
  const request = async (method: string, path: string, body?: unknown) => {
    const r = await fetch(address + path, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  const t0 = performance.now();
  const apps = await Promise.all(
    Array.from({ length: 110 }, (_, i) =>
      request('POST', base, {
        code: `app-${i}`,
        owner_user_id: account.user.id,
        criticality: 'high',
        product_id: null,
        reason: 'initial_setup',
      }),
    ),
  );
  assert.equal(apps.filter((r) => r.status === 201).length, 100);
  assert.equal(apps.filter((r) => r.status === 409).length, 10);
  const appId = apps.find((r) => r.status === 201)!.body.id;
  const writes = await Promise.all(
    Array.from({ length: 32 }, () =>
      request('PATCH', base + '/' + appId, {
        expected_version: 1,
        criticality: 'critical',
        reason: 'config_change',
      }),
    ),
  );
  assert.equal(writes.filter((r) => r.status === 200).length, 1);
  assert.equal(writes.filter((r) => r.status === 409).length, 31);
  const envPath = base + '/' + appId + '/environments';
  const environments = await Promise.all(
    Array.from({ length: 21 }, (_, i) =>
      request('POST', envPath, { code: `env-${i}`, kind: 'staging', reason: 'initial_setup' }),
    ),
  );
  assert.equal(environments.filter((r) => r.status === 201).length, 20);
  assert.equal(environments.filter((r) => r.status === 409).length, 1);
  const envId = environments.find((r) => r.status === 201)!.body.id;
  const componentPath = envPath + '/' + envId + '/components';
  const components = await Promise.all(
    Array.from({ length: 101 }, (_, i) =>
      request('POST', componentPath, {
        code: `component-${i}`,
        kind: 'service',
        dependency_ids: [],
        reason: 'initial_setup',
      }),
    ),
  );
  assert.equal(components.filter((r) => r.status === 201).length, 100);
  assert.equal(components.filter((r) => r.status === 409).length, 1);
  const count = await pool.query(
    "SELECT (SELECT count(*)::int FROM operations_applications) AS applications,(SELECT count(*)::int FROM operations_environments) AS environments,(SELECT count(*)::int FROM operations_components) AS components,(SELECT count(*)::int FROM audit_events WHERE action LIKE 'operations.%') AS audit",
  );
  assert.deepEqual(count.rows[0], {
    applications: 100,
    environments: 20,
    components: 100,
    audit: 221,
  });
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      scenario: 'operations-inventory-contention',
      requests: 264,
      expected: { created: 220, updated: 1, conflicts: 43, audit: 221 },
      observed: count.rows[0],
      duration_ms: Math.round(performance.now() - t0),
      fsync: 'on',
      audit_verified: true,
    }),
  );
} finally {
  await app?.close();
  await pool.end();
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await admin.end();
}
