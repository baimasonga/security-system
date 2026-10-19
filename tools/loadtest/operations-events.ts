// OPS-004: real loopback HTTP, disposable PostgreSQL schema, bounded retention; no external recipients.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { sha256Hex } from '@trust/crypto';
import { buildApp } from '../../services/platform-api/src/app.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
import { loadConfig } from '../../services/platform-api/src/config.ts';
import { applyMigrations, MIGRATIONS_DIR } from '../../services/platform-api/src/db/migrate.ts';
const url = process.env['DATABASE_URL'];
if (!url) throw new Error('DATABASE_URL required: disposable local database only');
const schema = 'ops_events_load_' + randomBytes(6).toString('hex');
const admin = new pg.Client({ connectionString: url });
await admin.connect();
const pool = new pg.Pool({ connectionString: url, options: `-c search_path=${schema}`, max: 2 });
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
let time = new Date('2026-10-19T00:00:00Z');
const clock = { now: () => time };
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
      operationsCredentialsEnabled: true,
      operationsIngestionEnabled: true,
      operationsHealthEnabled: true,
      mfaEncryptionKey: randomBytes(32).toString('hex'),
      scrypt: { N: 1024, r: 8, p: 1 },
    },
    { pool, clock },
  );
  app = await buildApp(c);
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const account = await c.auth.register({
    email: 'events-load@example.test',
    password: 'load-password-long-only',
  });
  const session = (
    await c.auth.login({ email: 'events-load@example.test', password: 'load-password-long-only' })
  ).token;
  const request = async (path: string, token: string, body: unknown) => {
    const r = await fetch(address + path, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return {
      status: r.status,
      body: (await r.json()) as {
        id?: string;
        accepted?: Array<{ id: string; disposition: string; received_at: string }>;
      },
    };
  };
  const base = `/v1/organizations/${account.personalOrg.id}/operations/applications`;
  const a = await request(base, session, {
    code: 'collector-fixture',
    owner_user_id: account.user.id,
    criticality: 'low',
    product_id: null,
    reason: 'initial_setup',
  });
  assert.equal(a.status, 201);
  const e = await request(base + '/' + a.body.id + '/environments', session, {
    code: 'staging',
    kind: 'staging',
    reason: 'initial_setup',
  });
  assert.equal(e.status, 201);
  const component = await request(
    base + '/' + a.body.id + '/environments/' + e.body.id + '/components',
    session,
    { code: 'converter', kind: 'worker', dependency_ids: [], reason: 'initial_setup' },
  );
  assert.equal(component.status, 201);
  // Synthetic local credential. Issuance/MFA is exercised by the HTTP behavioral suite separately.
  const keyId = 'opc_' + randomBytes(16).toString('hex'),
    secret = randomBytes(32).toString('hex');
  await pool.query(
    "INSERT INTO operations_credentials(id,org_id,application_id,environment_id,purpose,source,secret_hash,created_at,expires_at) VALUES($1,$2,$3,$4,'events:write','backend_report',$5,$6,$7)",
    [
      keyId,
      account.personalOrg.id,
      a.body.id,
      e.body.id,
      sha256Hex(secret),
      time,
      new Date(+time + 90 * 86400000),
    ],
  );
  const token = `ops_v1.${keyId}.${secret}`;
  const event = () => ({
    id: randomUUID(),
    component_id: component.body.id,
    occurred_at: time.toISOString(),
    type: 'component.heartbeat',
    attributes: { status: 'healthy' },
  });
  const original = event();
  const replies = await Promise.all(
    Array.from({ length: 20 }, () =>
      request('/v1/operations/events', token, { schema: 1, events: [original] }),
    ),
  );
  assert(replies.every((r) => r.status === 200));
  const dispositions = replies.flatMap((r) => r.body.accepted ?? []);
  assert.equal(dispositions.filter((r) => r.disposition === 'stored').length, 1);
  assert.equal(dispositions.filter((r) => r.disposition === 'duplicate').length, 19);
  const rejected = await request('/v1/operations/events', token, {
    schema: 1,
    events: [event(), { ...original, attributes: { status: 'unavailable' } }],
  });
  assert.equal(rejected.status, 409);
  for (let i = 0; i < 11; i++) {
    const response = await request('/v1/operations/events', token, {
      schema: 1,
      events: Array.from({ length: 100 }, event),
    });
    assert.equal(response.status, 200);
    assert.equal(response.body.accepted?.filter((r) => r.disposition === 'stored').length, 100);
  }
  const healthPath = base + '/' + a.body.id + '/environments/' + e.body.id + '/health';
  const healthResponses = await Promise.all(
    Array.from({ length: 20 }, () =>
      fetch(address + healthPath, { headers: { authorization: 'Bearer ' + session } }),
    ),
  );
  assert(healthResponses.every((r) => r.status === 200));
  for (const r of healthResponses)
    assert.equal(
      ((await r.json()) as { components: Array<{ status: string }> }).components[0]?.status,
      'healthy',
    );
  time = new Date(+time + 180000);
  const stale = await fetch(address + healthPath, {
    headers: { authorization: 'Bearer ' + session },
  });
  assert.equal(stale.status, 200);
  assert.equal(
    ((await stale.json()) as { components: Array<{ status: string }> }).components[0]?.status,
    'stale',
  );
  const before = (
    await pool.query(
      'SELECT count(*)::int AS count,sum(size_bytes)::bigint AS bytes FROM operations_events',
    )
  ).rows[0];
  assert.equal(before.count, 1101);
  const counters = (
    await pool.query(
      "SELECT key,count,bytes FROM operations_event_counters WHERE key LIKE 'storage:%' ORDER BY key",
    )
  ).rows;
  assert.equal(counters.length, 2);
  for (const row of counters) {
    assert.equal(Number(row.count), 1101);
    assert.equal(Number(row.bytes), Number(before.bytes));
  }
  await pool.query('UPDATE operations_event_counters SET count=10000 WHERE key=$1', [
    `day:env:${e.body.id}:2026-10-19`,
  ]);
  const capped = await Promise.all(
    [1, 2].map(() => request('/v1/operations/events', token, { schema: 1, events: [event()] })),
  );
  assert(capped.every((r) => r.status === 429));
  assert.equal(
    (await pool.query('SELECT count(*)::int AS count FROM operations_events')).rows[0].count,
    1101,
  );
  time = new Date(+time + 30 * 86400000);
  assert.equal(await c.operationsEvents.retain(), 1000);
  assert.equal(
    (await pool.query('SELECT count(*)::int AS count FROM operations_events')).rows[0].count,
    101,
  );
  assert.equal(await c.operationsEvents.retain(), 101);
  assert.equal(await c.operationsEvents.retain(), 0);
  for (const row of (
    await pool.query("SELECT count,bytes FROM operations_event_counters WHERE key LIKE 'storage:%'")
  ).rows) {
    assert.equal(Number(row.count), 0);
    assert.equal(Number(row.bytes), 0);
  }
  assert.equal(
    Number(
      (await pool.query('SELECT sum(count) AS count FROM operations_event_aggregates')).rows[0]
        .count,
    ),
    1101,
  );
  assert.equal(
    (await request('/v1/operations/events', token, { schema: 1, events: [original] })).status,
    422,
  );
  time = new Date(+time + 60 * 86400000);
  await c.operationsEvents.retain();
  assert.equal(
    (await pool.query('SELECT count(*)::int AS count FROM operations_event_aggregates')).rows[0]
      .count,
    0,
  );
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      scenario: 'operations-events-contention-retention',
      pool: 2,
      contenders: 20,
      stored: 1101,
      duplicate_receipts: 19,
      atomic_conflicts: 1,
      quota_refusals: 2,
      retention_batches: [1000, 101, 0],
      released_bytes: Number(before.bytes),
      remaining_storage_bytes: 0,
      aggregate_count_before_expiry: 1101,
      aggregate_count_after_expiry: 0,
      expired_retry_refused: true,
      audit_verified: true,
      fsync: 'on',
      health_read_contenders: 20,
      stale_after_180_seconds: true,
      duration_ms: Math.round(performance.now() - started),
    }),
  );
} finally {
  await app?.close();
  await pool.end();
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await admin.end();
}
