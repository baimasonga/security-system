// Correctness under contention: real HTTP, fsync-on disposable PostgreSQL, pool of two.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { buildApp } from '../../services/platform-api/src/app.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
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
  const c = await createContainer(
    {
      ...loadConfig({ NODE_ENV: 'test' }),
      operationsInventoryEnabled: true,
      operationsIncidentsEnabled: true,
      sharing: undefined,
      scrypt: { N: 1024, r: 8, p: 1 },
    },
    { pool },
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
  const path = scope + '/incidents';
  const input = {
    component_id: component.body.id,
    severity: 'warning',
    reason: 'security_response',
  };
  const storm = await Promise.all(Array.from({ length: 20 }, () => request('POST', path, input)));
  assert.ok(storm.every((r) => r.status === 200));
  assert.equal(storm.filter((r) => r.body.created).length, 1);
  const id = storm[0]!.body.incident!.id;
  assert.equal(new Set(storm.map((r) => r.body.incident!.id)).size, 1);
  const edits = await Promise.all(
    Array.from({ length: 20 }, () =>
      request('POST', `${path}/${id}/acknowledge`, { expected_version: 1, reason: 'incident_ack' }),
    ),
  );
  assert.equal(edits.filter((r) => r.status === 200).length, 1);
  assert.equal(edits.filter((r) => r.status === 409).length, 19);
  const reads = await Promise.all(Array.from({ length: 20 }, () => request('GET', path)));
  assert.ok(reads.every((r) => r.status === 200 && r.body.items?.length === 1));
  assert.equal(
    (
      await request('POST', `${path}/${id}/resolve`, {
        expected_version: 2,
        reason: 'incident_resolution',
      })
    ).body.state,
    'resolved',
  );
  const fresh = await request('POST', path, input);
  assert.equal(fresh.body.created, true);
  assert.notEqual(fresh.body.incident!.id, id);
  const audit = await pool.query(
    "SELECT action,count(*)::int AS n FROM audit_events WHERE action LIKE 'operations.incident.%' GROUP BY action ORDER BY action",
  );
  assert.deepEqual(audit.rows, [
    { action: 'operations.incident.acknowledged', n: 1 },
    { action: 'operations.incident.opened', n: 2 },
    { action: 'operations.incident.resolved', n: 1 },
  ]);
  const rows = await pool.query(
    'SELECT state,count(*)::int AS n FROM operations_incidents GROUP BY state ORDER BY state',
  );
  assert.deepEqual(rows.rows, [
    { state: 'open', n: 1 },
    { state: 'resolved', n: 1 },
  ]);
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      scenario: 'manual-incidents-contention',
      pool: 2,
      open_contenders: 20,
      created: 1,
      edit_contenders: 20,
      acknowledged: 1,
      stale_refusals: 19,
      concurrent_reads: 20,
      new_after_resolution: true,
      incident_rows: 2,
      audit_events: 4,
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
