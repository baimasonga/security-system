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
const schema = 'ops_posture_load_' + randomBytes(6).toString('hex');
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
  const time = Date.now();
  const clock = { now: () => new Date(time) };
  const c = await createContainer(
    {
      ...loadConfig({ NODE_ENV: 'test' }),
      operationsInventoryEnabled: true,
      operationsIncidentsEnabled: true,
      operationsHealthEnabled: true,
      operationsIngestionEnabled: true,
      operationsAutomationEnabled: true,
      operationsPostureEnabled: true,
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
      body: (await r.json()) as { id: string },
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
  const scan = {
    component_id: component.body.id,
    source: 'github_dependabot',
    revision: 'a'.repeat(40),
    run_id: '1',
    completed_at: clock.now().toISOString(),
    outcome: 'completed',
    findings: [
      { fingerprint: 'b'.repeat(64), severity: 'critical', advisory_id: 'CVE-2026-12345' },
    ],
    reason: 'initial_setup',
  };
  const imports = await Promise.all(
    Array.from({ length: 20 }, () => request('POST', scope + '/security/scans', scan)),
  );
  assert.equal(imports.filter((r) => r.status === 201).length, 1);
  assert.equal(imports.filter((r) => r.status === 200).length, 19);
  const finding = (await pool.query('SELECT id FROM operations_security_findings')).rows[0];
  const edits = await Promise.all(
    Array.from({ length: 20 }, () =>
      request('PATCH', scope + '/security/findings/' + finding.id, {
        expected_version: 1,
        state: 'acknowledged',
        assignee_user_id: account.user.id,
        reason: 'assignment',
      }),
    ),
  );
  assert.equal(edits.filter((r) => r.status === 200).length, 1);
  assert.equal(edits.filter((r) => r.status === 409).length, 19);
  const recovery = {
    component_id: component.body.id,
    kind: 'restore',
    started_at: new Date(time - 60000).toISOString(),
    completed_at: clock.now().toISOString(),
    recovery_point_at: new Date(time - 120000).toISOString(),
    outcome: 'succeeded',
    integrity_check: 'passed',
    application_check: 'passed',
    audit_check: 'passed',
    artifact_digest: 'c'.repeat(64),
    target_rpo_seconds: 300,
    target_rto_seconds: 7200,
    reason: 'initial_setup',
  };
  const recoveries = await Promise.all(
    Array.from({ length: 20 }, () => request('POST', scope + '/security/recovery', recovery)),
  );
  assert.equal(recoveries.filter((r) => r.status === 201).length, 1);
  assert.equal(recoveries.filter((r) => r.status === 200).length, 19);
  const evidence = await pool.query(
    'SELECT kind,count(*)::int AS n FROM operations_security_evidence GROUP BY kind ORDER BY kind',
  );
  assert.deepEqual(evidence.rows, [
    { kind: 'recovery', n: 1 },
    { kind: 'scan', n: 1 },
  ]);
  assert.deepEqual(
    (await pool.query('SELECT state,version FROM operations_security_findings')).rows,
    [{ state: 'acknowledged', version: 2 }],
  );
  for (const action of [
    'operations.scan.imported',
    'operations.finding.triaged',
    'operations.recovery.recorded',
  ])
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM audit_events WHERE action=$1', [action]))
        .rows[0].n,
      1,
    );
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      result: 'passed',
      concurrentRequests: 60,
      scanReports: 1,
      findings: 1,
      successfulEdits: 1,
      conflictingEdits: 19,
      recoveryReports: 1,
      auditVerified: true,
      elapsedMs: Math.round(performance.now() - started),
    }),
  );
} finally {
  await app?.close();
  await pool.end();
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await admin.end();
}
