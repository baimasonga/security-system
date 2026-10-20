// Security mutations run in an isolated source copy with its own workspace links.
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('../', import.meta.url));
const copy = mkdtempSync(join(tmpdir(), 'operations-incidents-mutations-'));
const domain = 'packages/operations/test/incidents.test.ts';
const api = 'services/platform-api/test/operations-incidents.test.ts';
const service = 'packages/operations/src/incidents.ts';
const cases = [
  [service, 'if (!this.#d.enabled())', 'if (false)', domain],
  [
    service,
    "await authority.authorize(p, scope.orgId, write ? 'ops:manage_incidents' : 'ops:read');",
    'await Promise.resolve();',
    domain,
  ],
  [
    service,
    'await this.#authorize(p, scope, write, authority);',
    'await Promise.resolve();',
    domain,
  ],
  [
    service,
    'if (!(await authority.sessionActive?.(p, this.#d.clock.now())))',
    'if (false)',
    domain,
  ],
  [service, 'await authority.assertWritable(scope.orgId);', 'await Promise.resolve();', domain],
  [service, 'await tx.audit.append({', 'await Promise.resolve({', domain],
  [service, '!(await authority.activeMember(scope.orgId, input.assigneeUserId))', 'false', domain],
  [service, "old.state === 'resolved' ||", 'false ||', domain],
  [service, 'old.version !== input.expectedVersion ||', 'false ||', domain],
  [service, "[a, e, c].some((r) => r.state !== 'active')", 'false', domain],
  [
    service,
    'if (active) return { incident: active, created: false };',
    'if (false) return { incident: active, created: false };',
    domain,
  ],
  [service, 'if (rows.length >= 1000)', 'if (false)', domain],
  [service, 'Math.max(+old.updatedAt, +this.#d.clock.now())', '+this.#d.clock.now()', domain],
  [
    'packages/operations/src/memory.ts',
    'repo.incidents = structuredClone(this.incidents);',
    '',
    domain,
  ],
  ['packages/operations/src/memory.ts', 'this.incidents = repo.incidents;', '', domain],
  [
    'packages/auth/src/rbac.ts',
    '  member: [',
    "  member: ['ops:read','ops:manage_incidents',",
    api,
  ],
];
let killed = 0;
function run(project, test, pattern) {
  return spawnSync(
    process.execPath,
    [
      join(copy, 'node_modules/vitest/vitest.mjs'),
      'run',
      '--project',
      project,
      test,
      ...(pattern ? ['-t', pattern] : []),
    ],
    { cwd: copy, encoding: 'utf8' },
  );
}
function mutate(file, before, after, project, test, pattern) {
  const path = join(copy, file),
    original = readFileSync(path, 'utf8');
  assert.ok(original.includes(before), `missing anchor: ${before}`);
  try {
    writeFileSync(path, original.replaceAll(before, after));
    const result = run(project, test, pattern);
    assert.equal(result.signal, null);
    assert.notEqual(result.status, 0, `survived: ${before}`);
    assert.match(result.stdout + result.stderr, /AssertionError/);
    killed++;
    console.log(`Killed: ${before}`);
  } finally {
    writeFileSync(path, original);
  }
}
try {
  for (const dir of ['packages', 'services', 'tests', 'tools', 'docs'])
    cpSync(join(root, dir), join(copy, dir), { recursive: true });
  for (const file of ['package.json', 'package-lock.json', 'tsconfig.json', 'vitest.config.ts'])
    cpSync(join(root, file), join(copy, file));
  const install = spawnSync(
    'npm',
    [
      'ci',
      '--offline',
      ...(process.env['NPM_CONFIG_CACHE'] ? ['--cache', process.env['NPM_CONFIG_CACHE']] : []),
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
    ],
    { cwd: copy, encoding: 'utf8' },
  );
  assert.equal(install.status, 0, install.stdout + install.stderr);
  for (const test of [domain, api]) {
    const result = run('unit', test);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  }
  for (const [file, before, after, test] of cases) mutate(file, before, after, 'unit', test);
  if (process.env.DATABASE_URL) {
    const test = 'services/platform-api/test/operations-events-store.db.test.ts';
    const result = run('db', test);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    mutate(
      'services/platform-api/src/db/pg-operations-store.ts',
      'WHERE org_id=$1 AND id=$2',
      'WHERE id=$2 AND $1::text IS NOT NULL',
      'db',
      test,
    );
    mutate(
      'services/platform-api/migrations/0022_operations_incidents.sql',
      "OR OLD.state='resolved'",
      'OR false',
      'db',
      test,
    );
    mutate(
      'services/platform-api/migrations/0022_operations_incidents.sql',
      'CREATE UNIQUE INDEX operations_incidents_active_idx',
      'CREATE INDEX operations_incidents_active_idx',
      'db',
      test,
    );
  }
  if (process.env.CHROMIUM_PATH) {
    const test = 'tests/browser/operations.test.ts',
      pattern = 'late mutation response';
    const result = run('portal', test, pattern);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    mutate(
      'services/platform-api/src/web/operations.mjs',
      'if (current(n)) await show(reload);',
      'await show(reload);',
      'portal',
      test,
      pattern,
    );
  }
  console.log(`${killed} incident mutations killed; source copy restored and removed.`);
} finally {
  rmSync(copy, { recursive: true, force: true });
}
