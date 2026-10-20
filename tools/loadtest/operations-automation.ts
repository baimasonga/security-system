// Correctness under contention: real HTTP, fsync-on disposable PostgreSQL, pool of two.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { buildApp } from '../../services/platform-api/src/app.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
import { PgInventoryStore } from '../../services/platform-api/src/db/pg-operations-store.ts';
import { loadConfig } from '../../services/platform-api/src/config.ts';
import { applyMigrations, MIGRATIONS_DIR } from '../../services/platform-api/src/db/migrate.ts';
const url = process.env['DATABASE_URL'];
if (!url) throw new Error('DATABASE_URL required: disposable local database only');
const schema = 'ops_incidents_load_' + randomBytes(6).toString('hex');
const admin = new pg.Client({ connectionString: url });
await admin.connect();
const pool = new pg.Pool({ connectionString: url, options: `-c search_path=${schema}`, max: 2 });
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
const started = performance.now();
try {
  assert.equal((await admin.query('SHOW fsync')).rows[0].fsync, 'on');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const migrator = await pool.connect();
  try {
    await applyMigrations(migrator, MIGRATIONS_DIR);
  } finally {
    migrator.release();
  }
  let time = Date.now();
  const clock = { now: () => new Date(time) };
  const c = await createContainer(
    {
      ...loadConfig({ NODE_ENV: 'test' }),
      operationsInventoryEnabled: true,
      operationsIncidentsEnabled: true,
      operationsHealthEnabled: true,
      operationsIngestionEnabled: true,
      operationsAutomationEnabled: true,
      sharing: undefined,
      scrypt: { N: 1024, r: 8, p: 1 },
    },
    { pool, clock },
  );
  app = await buildApp(c);
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const account = await c.auth.register({
    email: 'incidents-load@example.test',
    password: 'synthetic-load-password-long',
  });
  const session = (
    await c.auth.login({
      email: 'incidents-load@example.test',
      password: 'synthetic-load-password-long',
    })
  ).token;
  async function request(method: string, path: string, body?: unknown) {
    const r = await fetch(address + path, {
      method,
      headers: { authorization: 'Bearer ' + session, 'content-type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return {
      status: r.status,
      body: (await r.json()) as {
        id?: string;
        created?: boolean;
        incident?: { id: string };
        items?: unknown[];
        state?: string;
      },
    };
  }
  const base = `/v1/organizations/${account.personalOrg.id}/operations/applications`;
  const a = await request('POST', base, {
    code: 'incident-load',
    owner_user_id: account.user.id,
    criticality: 'low',
    product_id: null,
    reason: 'initial_setup',
  });
  assert.equal(a.status, 201);
  const e = await request('POST', `${base}/${a.body.id}/environments`, {
    code: 'staging',
    kind: 'staging',
    reason: 'initial_setup',
  });
  assert.equal(e.status, 201);
  const scope = `${base}/${a.body.id}/environments/${e.body.id}`;
  const component = await request('POST', scope + '/components', {
    code: 'worker',
    kind: 'worker',
    dependency_ids: [],
    reason: 'initial_setup',
  });
  assert.equal(component.status, 201);
  const r = await request('POST', scope + '/rules', {
    component_id: component.body.id,
    kind: 'heartbeat',
    event_type: null,
    threshold: 1,
    window_seconds: 60,
    severity: 'warning',
    runbook: 'check_scanner',
    reason: 'initial_setup',
  });
  assert.equal(r.status, 201);
  const store = new PgInventoryStore(pool, clock);
  const identity = {
    orgId: account.personalOrg.id,
    applicationId: a.body.id!,
    environmentId: e.body.id!,
  };
  const heartbeat = (status: 'healthy' | 'unavailable') =>
    store.transaction(identity.orgId, (tx) =>
      tx.recordHeartbeat({
        ...identity,
        componentId: component.body.id!,
        status,
        occurredAt: clock.now(),
        receivedAt: clock.now(),
        expiresAt: new Date(time + 86400000),
      }),
    );
  await heartbeat('unavailable');
  assert.equal((await request('POST', scope + '/rules/evaluate', {})).status, 200);
  time += 60000;
  const storm = await Promise.all(
    Array.from({ length: 20 }, () => request('POST', scope + '/rules/evaluate', {})),
  );
  assert.ok(storm.every((r) => r.status === 200));
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM operations_incidents')).rows[0].n,
    1,
  );
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM operations_alert_notifications')).rows[0].n,
    1,
  );
  await Promise.all(
    Array.from({ length: 20 }, () => c.operationsAutomation.deliverPending(identity)),
  );
  assert.deepEqual(
    (await pool.query('SELECT state,attempts FROM operations_alert_notifications')).rows,
    [{ state: 'delivered', attempts: 1 }],
  );
  time += 1;
  await heartbeat('healthy');
  assert.equal((await request('POST', scope + '/rules/evaluate', {})).status, 200);
  time += 60000;
  await heartbeat('healthy');
  assert.equal((await request('POST', scope + '/rules/evaluate', {})).status, 200);
  assert.deepEqual((await pool.query('SELECT state FROM operations_incidents')).rows, [
    { state: 'resolved' },
  ]);
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM operations_alert_notifications')).rows[0].n,
    2,
  );
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      scenario: 'automatic-alerts-contention',
      pool: 2,
      evaluation_contenders: 20,
      incidents_created: 1,
      delivery_contenders: 20,
      delivery_attempts: 1,
      recovered: true,
      notification_intents: 2,
      audit_verified: true,
      fsync: 'on',
      duration_ms: Math.round(performance.now() - started),
    }),
  );
} finally {
  await app?.close();
  await pool.end();
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await admin.end();
}
