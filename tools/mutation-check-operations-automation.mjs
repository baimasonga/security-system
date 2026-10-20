import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('../', import.meta.url));
const copy = mkdtempSync(join(tmpdir(), 'ops-automation-mutations-'));
const service = 'packages/operations/src/automation.ts';
const domain = 'packages/operations/test/automation.test.ts',
  api = 'services/platform-api/test/operations-automation.test.ts';
const cases = [
  [service, 'if (!this.#d.enabled()) throw missing();', 'if (false) throw missing();', domain],
  [
    service,
    "await authority.authorize(p, scope.orgId, write ? 'ops:manage_incidents' : 'ops:read');",
    'await Promise.resolve();',
    api,
  ],
  [
    service,
    'if (!(await authority.sessionActive?.(p, this.#d.clock.now())))',
    'if (false)',
    domain,
  ],
  [
    service,
    'if (write) await authority.assertWritable(scope.orgId);',
    'if (false) await authority.assertWritable(scope.orgId);',
    domain,
  ],
  [
    service,
    'if (old.version !== input.expectedVersion) throw conflict();',
    'if (false) throw conflict();',
    api,
  ],
  [
    service,
    "if (!old.enabled || !c || [a, e, c].some((r) => r.state !== 'active'))",
    'if (!c)',
    domain,
  ],
  [
    service,
    'if (rule.maintenanceUntil && rule.maintenanceUntil > now) return;',
    'if (false) return;',
    domain,
  ],
  [
    service,
    'if (!(await authority.activeMember(rule.orgId, rule.createdByUserId))) return;',
    'if (false) return;',
    domain,
  ],
  [service, 'current.claimToken !== claimed.claimToken ||', 'false ||', domain],
  [service, 'n.deadline <= now ||', 'false ||', domain],
  [service, 'await tx.audit.append({', 'await Promise.resolve({', domain],
  [service, 'input.threshold < 1 ||', 'false ||', domain],
  [service, 'input.windowSeconds > 3600 ||', 'false ||', domain],
  [service, 'resource.version === 1', 'true', domain],
  [
    service,
    "const healthy = !!fresh && eligible.status === 'healthy' && !bad;",
    'const healthy = !bad;',
    domain,
  ],
  [
    'packages/auth/src/rbac.ts',
    '  member: [',
    "  member: ['ops:read','ops:manage_incidents',",
    api,
  ],
];
const run = (test) =>
  spawnSync(
    process.execPath,
    [join(copy, 'node_modules/vitest/vitest.mjs'), 'run', '--project', 'unit', test],
    { cwd: copy, encoding: 'utf8', env: process.env, timeout: 120000 },
  );
try {
  for (const dir of ['packages', 'services', 'tests', 'tools', 'docs'])
    cpSync(join(root, dir), join(copy, dir), { recursive: true });
  for (const file of ['package.json', 'package-lock.json', 'tsconfig.json', 'vitest.config.ts'])
    cpSync(join(root, file), join(copy, file));
  const install = spawnSync(
    'npm',
    ['ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'],
    { cwd: copy, encoding: 'utf8', env: process.env },
  );
  assert.equal(install.status, 0, install.stdout + install.stderr);
  for (const test of [domain, api]) {
    const baseline = run(test);
    assert.equal(baseline.status, 0, baseline.stdout + baseline.stderr);
  }
  let killed = 0;
  for (const [file, before, after, test] of cases) {
    const path = join(copy, file),
      original = readFileSync(path, 'utf8');
    assert.ok(original.includes(before), `missing mutation anchor: ${before}`);
    try {
      writeFileSync(path, original.replaceAll(before, after));
      const result = run(test);
      assert.equal(result.signal, null);
      assert.notEqual(result.status, 0, `survived: ${before}`);
      assert.match(result.stdout + result.stderr, /AssertionError|expected .* to/);
      killed++;
      console.log('Killed:', before);
    } finally {
      writeFileSync(path, original);
    }
  }
  console.log(`${killed} automation security mutations killed.`);
} finally {
  rmSync(copy, { recursive: true, force: true });
}
