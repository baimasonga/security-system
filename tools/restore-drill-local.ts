// Isolated fixture exercise only: fixed loopback PostgreSQL and local Docker socket.
// Creates/drops only freshly generated posture_drill_* databases; never production.
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import pg from 'pg';
import { applyMigrations, MIGRATIONS_DIR } from '../services/platform-api/src/db/migrate.ts';
import { createContainer } from '../services/platform-api/src/container.ts';
import { loadConfig } from '../services/platform-api/src/config.ts';
const base = 'postgres://postgres@127.0.0.1:55432/postgres';
const suffix = randomBytes(6).toString('hex'),
  sourceName = 'posture_drill_source_' + suffix,
  targetName = 'posture_drill_target_' + suffix;
const admin = new pg.Client({ connectionString: base });
await admin.connect();
const pools: pg.Pool[] = [];
let source: Awaited<ReturnType<typeof createContainer>> | undefined,
  target: Awaited<ReturnType<typeof createContainer>> | undefined,
  snapshot: pg.PoolClient | undefined;
const childEnv = { ...process.env };
for (const k of [
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'DOCKER_TLS',
  'DOCKER_TLS_VERIFY',
  'DOCKER_CERT_PATH',
])
  delete childEnv[k];
const docker = (args: string[], input?: Buffer) =>
  execFileSync('docker', ['--host', 'unix:///var/run/docker.sock', ...args], {
    env: childEnv,
    input,
    maxBuffer: 64 * 1024 * 1024,
  });
try {
  assert.equal((await admin.query('SHOW fsync')).rows[0].fsync, 'on');
  await admin.query(`CREATE DATABASE ${sourceName}`);
  await admin.query(`CREATE DATABASE ${targetName}`);
  const makePool = (name: string) => {
    const url = new URL(base);
    url.pathname = '/' + name;
    const pool = new pg.Pool({ connectionString: url.toString(), max: 2 });
    pools.push(pool);
    return pool;
  };
  const sourcePool = makePool(sourceName),
    targetPool = makePool(targetName);
  const migrator = await sourcePool.connect();
  try {
    await applyMigrations(migrator, MIGRATIONS_DIR);
  } finally {
    migrator.release();
  }
  const config = {
    ...loadConfig({ NODE_ENV: 'test' }),
    operationsInventoryEnabled: true,
    operationsPostureEnabled: true,
    sharing: undefined,
    scrypt: { N: 1024, r: 8, p: 1 },
  };
  source = await createContainer(config, { pool: sourcePool });
  const user = await source.auth.register({
    email: 'restore-fixture@example.test',
    password: 'synthetic-restore-password',
  });
  const login = await source.auth.login({
    email: 'restore-fixture@example.test',
    password: 'synthetic-restore-password',
  });
  const p = await source.auth.authenticate(login.token);
  const a = await source.operations.createApplication(p, user.personalOrg.id, {
    code: 'restore-fixture',
    ownerUserId: user.user.id,
    criticality: 'low',
    productId: null,
    reason: 'initial_setup',
  });
  const e = await source.operations.createEnvironment(
    p,
    { orgId: user.personalOrg.id, applicationId: a.id },
    { code: 'isolated-test', kind: 'staging', reason: 'initial_setup' },
  );
  const scope = { orgId: user.personalOrg.id, applicationId: a.id, environmentId: e.id };
  const component = await source.operations.createComponent(p, scope, {
    code: 'test-db',
    kind: 'database',
    dependencyIds: [],
    reason: 'initial_setup',
  });
  await source.operationsPosture.importScan(p, scope, {
    component_id: component.id,
    source: 'github_dependabot',
    revision: 'a'.repeat(40),
    run_id: '1',
    completed_at: new Date().toISOString(),
    outcome: 'completed',
    findings: [{ fingerprint: 'b'.repeat(64), severity: 'high', advisory_id: 'CVE-2026-12345' }],
    reason: 'initial_setup',
  });
  assert.equal((await source.audit.verifyChain()).ok, true);
  snapshot = await sourcePool.connect();
  await snapshot.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const mark = (
    await snapshot.query('SELECT pg_export_snapshot() AS id,clock_timestamp() AS point')
  ).rows[0];
  const dump = docker([
    'exec',
    'onboarding-security-postgres',
    'pg_dump',
    '-U',
    'postgres',
    '-d',
    sourceName,
    '-Fc',
    '--snapshot',
    mark.id,
  ]);
  await snapshot.query('COMMIT');
  snapshot.release();
  snapshot = undefined;
  await source.auth.register({
    email: 'after-snapshot@example.test',
    password: 'synthetic-restore-password',
  });
  const start = performance.now();
  const startedAt = new Date();
  docker(
    [
      'exec',
      '-i',
      'onboarding-security-postgres',
      'pg_restore',
      '-U',
      'postgres',
      '-d',
      targetName,
      '--no-owner',
      '--no-privileges',
      '--exit-on-error',
    ],
    dump,
  );
  target = await createContainer(config, { pool: targetPool });
  assert.equal(
    (await targetPool.query('SELECT count(*)::int AS n FROM schema_migrations')).rows[0].n,
    24,
  );
  assert.equal((await targetPool.query('SELECT count(*)::int AS n FROM users')).rows[0].n, 1);
  assert.equal((await sourcePool.query('SELECT count(*)::int AS n FROM users')).rows[0].n, 2);
  assert.equal((await target.audit.verifyChain()).ok, true);
  const view = await target.operationsPosture.read(p, scope);
  assert.equal(view.scans.items.length, 1);
  assert.equal(view.findings.items.length, 1);
  assert.equal(view.independentlyVerified, false);
  console.log(
    JSON.stringify({
      result: 'passed',
      scope: 'isolated synthetic logical backup/restore only',
      schemaMigrations: 24,
      recoveredFindingSnapshots: 1,
      postSnapshotUsersExcluded: 1,
      integrityCheck: 'passed',
      applicationCheck: 'passed',
      auditCheck: 'passed',
      snapshotAgeAtRestoreSeconds: Math.floor((+startedAt - +new Date(mark.point)) / 1000),
      recoveryElapsedMs: Math.round(performance.now() - start),
      artifactDigest: createHash('sha256').update(dump).digest('hex'),
      productionBackupVerified: false,
    }),
  );
} finally {
  if (snapshot) {
    await snapshot.query('ROLLBACK').catch(() => {});
    snapshot.release();
  }
  await source?.close();
  await target?.close();
  for (const pool of pools) await pool.end();
  for (const name of [sourceName, targetName]) {
    assert.match(name, /^posture_drill_(source|target)_[a-f0-9]{12}$/);
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  }
  await admin.end();
}
