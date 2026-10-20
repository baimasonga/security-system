// Security evidence and navigation controls must fail their assertions when deliberately broken.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const file = 'services/platform-api/src/web/operations.mjs';
const original = readFileSync(file, 'utf8');
const mutations = [
  ['restore-separation', "r.kind === 'restore'", 'true'],
  [
    'completion-order',
    'new Date(b.completed_at) > new Date(a.completed_at)',
    'new Date(b.completed_at) < new Date(a.completed_at)',
  ],
  ['open-finding-states', "['open', 'acknowledged'].includes(f.state)", 'true'],
  [
    'truncation-disclosure',
    'partial: view.scans.truncated || view.findings.truncated || view.recovery.truncated',
    'partial: false',
  ],
  ['stale-evidence', "scan.freshness !== 'current' || restore.freshness !== 'current'", 'false'],
  ['application-cap', 'apps.items.slice(0, 10)', 'apps.items.slice(0, 100)', 'bounds inventory'],
  [
    'environment-cap',
    'pages[i].items.slice(0, 5)',
    'pages[i].items.slice(0, 100)',
    'bounds inventory',
  ],
  ['late-batches', 'if (!current(n)) return [];', '', 'stops new batches', true],
  ['authorization-refusal', '[401, 403].includes(error.status)', 'false', 'refuses authorization'],
  ['attention-order', 'a.rank - b.rank ||', '', 'prioritizes open critical'],
];
mkdirSync('/tmp/security-overview-mutations', { recursive: true });
for (const [name, needle, replacement, browserCase, all] of mutations) {
  if (!original.includes(needle)) throw Error('Mutation anchor missing: ' + name);
  try {
    writeFileSync(
      file,
      all ? original.replaceAll(needle, replacement) : original.replace(needle, replacement),
    );
    const args = browserCase
      ? [
          'vitest',
          'run',
          '--project',
          'portal',
          'tests/browser/operations.test.ts',
          '-t',
          browserCase,
        ]
      : [
          'vitest',
          'run',
          '--project',
          'unit',
          'services/platform-api/test/security-overview.test.mjs',
        ];
    const result = spawnSync('npx', args, { encoding: 'utf8', timeout: 90000, env: process.env });
    const log = (result.stdout ?? '') + (result.stderr ?? '');
    writeFileSync('/tmp/security-overview-mutations/' + name + '.log', log);
    if (result.status === 0) throw Error('Mutation survived: ' + name);
    if (!/FAIL\s/.test(log)) throw Error('Mutation did not reach an assertion: ' + name);
    console.log('KILLED ' + name);
  } finally {
    writeFileSync(file, original);
  }
}
console.log('PASS: ' + mutations.length + ' overview security mutations killed');
