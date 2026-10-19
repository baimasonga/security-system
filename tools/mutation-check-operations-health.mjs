// Mutations run only in a disposable source copy; active checkout/test processes stay untouched.
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('../', import.meta.url));
const copy = mkdtempSync(join(tmpdir(), 'operations-health-mutations-'));
const cases = [
  ['health.ts', 'age > 120000', 'age > 86400000'],
  ['health.ts', 'age < 0 ||', 'false ||'],
  ['health.ts', '>= 180000', '>= 86400000'],
  ['health.ts', 'if (!this.#d.enabled())', 'if (false)'],
  ['health.ts', '+to - +from > 86400000', 'false'],
  ['health.ts', "deps.includes('unavailable')", 'false'],
  ['health.ts', '!row.monitoringActive ||', 'false ||'],
  ['events-memory.ts', 'row.occurredAt > old.occurredAt', 'row.receivedAt > old.receivedAt'],
  ['events-memory.ts', 'HEARTBEAT_RANK[row.status] > HEARTBEAT_RANK[old.status]', 'true'],
  ['events-memory.ts', 'this.eventAggregates, this.heartbeats', 'this.eventAggregates'],
  ['health.ts', 'await this.#d.authorize(p, scope.orgId', 'await Promise.resolve(p, scope.orgId'],
];
const pgCases = [
  [
    'EXCLUDED.occurred_at>operations_heartbeats.occurred_at',
    'EXCLUDED.occurred_at>=operations_heartbeats.occurred_at',
  ],
  [
    'org_id=$1 AND application_id=$2 AND environment_id=$3 AND component_id=$4',
    'org_id=$1 OR application_id=$2 AND environment_id=$3 AND component_id=$4',
  ],
];
function run(project, test) {
  return spawnSync(
    process.execPath,
    [join(root, 'node_modules/vitest/vitest.mjs'), 'run', '--project', project, test],
    { cwd: copy, encoding: 'utf8' },
  );
}
function mutate(file, before, after, project, test) {
  const path = join(copy, file),
    original = readFileSync(path, 'utf8');
  assert.ok(original.includes(before), `missing anchor: ${before}`);
  try {
    writeFileSync(path, original.replaceAll(before, after));
    const result = run(project, test);
    assert.equal(result.signal, null);
    assert.notEqual(result.status, 0, `survived: ${before}`);
    assert.match(result.stdout + result.stderr, /AssertionError/);
    console.log(`Killed: ${before}`);
  } finally {
    writeFileSync(path, original);
  }
}
try {
  for (const dir of ['packages', 'services', 'tests', 'tools', 'docs'])
    cpSync(join(root, dir), join(copy, dir), { recursive: true });
  for (const file of ['package.json', 'tsconfig.json', 'vitest.config.ts'])
    cpSync(join(root, file), join(copy, file));
  symlinkSync(join(root, 'node_modules'), join(copy, 'node_modules'), 'dir');
  const test = 'packages/operations/test/health.test.ts';
  const baseline = run('unit', test);
  assert.equal(baseline.status, 0, baseline.stdout + baseline.stderr);
  for (const [file, before, after] of cases)
    mutate('packages/operations/src/' + file, before, after, 'unit', test);
  if (process.env.DATABASE_URL) {
    const dbTest = 'services/platform-api/test/operations-events-store.db.test.ts';
    const dbBaseline = run('db', dbTest);
    assert.equal(dbBaseline.status, 0, dbBaseline.stdout + dbBaseline.stderr);
    for (const [before, after] of pgCases)
      mutate('services/platform-api/src/db/pg-operations-events.ts', before, after, 'db', dbTest);
    console.log('13 mutations killed, including PostgreSQL ordering and scope');
  } else console.log('11 mutations killed; set DATABASE_URL to include two PostgreSQL mutations');
} finally {
  rmSync(copy, { recursive: true, force: true });
}
