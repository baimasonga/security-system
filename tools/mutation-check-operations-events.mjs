// Run in an isolated checkout with no other tests importing these sources.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const service = 'packages/operations/src/events.ts';
const cases = [
  [service, "exact(value, ['schema', 'events']);", 'void value;', 'rejects source spoofing'],
  [
    service,
    'exact(event.attributes, Object.keys(rules));',
    'void rules;',
    'rejects source spoofing',
  ],
  [service, '!rule.includes(v)', 'false', 'runtime numeric bounds'],
  [service, '!Number.isSafeInteger(v)', 'false', 'runtime numeric bounds'],
  [service, 'times.length >= 60', 'false', 'sliding request'],
  [service, 'at < +now - DAY || at > +now + 300000', 'false', 'occurrence clock bounds'],
  [
    service,
    'component.environmentId !== identity.environmentId',
    'false',
    'real component from a different environment',
  ],
  [service, "component.state !== 'active'", 'false', 'disabled component'],
  [
    service,
    "Buffer.from(stored.contentHash, 'hex')",
    "Buffer.from(hash, 'hex')",
    'deduplicates canonical retries',
  ],
  [service, 'old && old.hash !== hash', 'false', 'mixed stale'],
  [
    service,
    'count > maxCount || totalBytes > maxBytes',
    'false || totalBytes > maxBytes',
    'sliding request',
  ],
  [
    service,
    'count > maxCount || totalBytes > maxBytes',
    'count > maxCount || false',
    'sliding request',
  ],
  [service, 'counter.bytes - release.bytes', 'counter.bytes', 'releases bytes atomically'],
  [
    'packages/operations/src/memory.ts',
    'repo.events = structuredClone(this.events);',
    'repo.events = this.events;',
    'withholds acknowledgements',
  ],
];
cases.push(
  [
    service,
    'Object.entries(e.attributes).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))',
    'Object.entries(e.attributes)',
    'reordered attributes',
  ],
  [
    'packages/operations/src/events-memory.ts',
    '.sort(([, a], [, b]) => +a.expiresAt - +b.expiresAt)\n      .slice(0, limit)',
    '.sort(([, a], [, b]) => +a.expiresAt - +b.expiresAt)\n      .slice(0, limit + 1)',
    'bounds each retention deletion',
  ],
);
cases.push(
  [
    service,
    'Buffer.byteLength(JSON.stringify({ schema: 1, events })) > 262144',
    'false',
    'byte cap below',
  ],
  [service, 'return { ok: false as const, error };', 'throw error;', 'fixed request charges'],
);
const run = (pattern) =>
  spawnSync(
    process.execPath,
    [
      'node_modules/vitest/vitest.mjs',
      'run',
      '--project',
      'unit',
      'packages/operations/test/events.test.ts',
      'services/platform-api/test/operations-events.test.ts',
      ...(pattern ? ['--testNamePattern', pattern] : []),
    ],
    { cwd: root, encoding: 'utf8' },
  );
const baseline = run();
assert.equal(baseline.status, 0, baseline.stdout + baseline.stderr);
for (const [file, before, after, pattern] of cases) {
  const path = new URL(file, `file://${root}`),
    original = readFileSync(path, 'utf8');
  assert.equal(original.split(before).length - 1, 1, `anchor count: ${before}`);
  try {
    writeFileSync(path, original.replace(before, after));
    const result = run(pattern);
    assert.equal(result.signal, null);
    assert.notEqual(result.status, 0, `survived: ${before}`);
    assert.match(result.stdout + result.stderr, /AssertionError/);
    console.log(`Killed: ${before}`);
  } finally {
    writeFileSync(path, original);
  }
}
console.log(`${cases.length} mutations killed; source restored`);
