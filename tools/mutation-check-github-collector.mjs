// Break controls one at a time; each run must reach a failing assertion. Always restore source.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const file = 'tools/collect-github-security.ts';
const original = readFileSync(file, 'utf8');
const mutations = [
  ['provider-status', 'response.status !== 200 ||', 'false ||'],
  ['complete-pagination', "response.headers.has('link') ||", 'false ||'],
  ['stream-cap', 'if (size > maxBytes) throw refused();', 'if (false) throw refused();'],
  ['commit-binding', "(commit as Record<string, unknown>)['sha'] !== options.revision", 'false'],
  ['redirect-refusal', "redirect: 'error'", "redirect: 'follow'"],
  ['token-required', '!d.token ||', 'false ||'],
  [
    'fixed-destination',
    "const API = 'https://api.github.com';",
    "const API = 'https://attacker.invalid';",
  ],
];
mkdirSync('/tmp/github-collector-mutations', { recursive: true });
for (const [name, needle, replacement] of mutations) {
  if (!original.includes(needle)) throw Error('Mutation anchor missing: ' + name);
  try {
    writeFileSync(file, original.replace(needle, replacement));
    const result = spawnSync(
      'npx',
      ['vitest', 'run', '--project', 'unit', 'packages/operations/test/github-collector.test.ts'],
      { encoding: 'utf8', timeout: 60000 },
    );
    const log = (result.stdout ?? '') + (result.stderr ?? '');
    writeFileSync('/tmp/github-collector-mutations/' + name + '.log', log);
    if (result.status === 0) throw Error('Mutation survived: ' + name);
    if (!/FAIL\s/.test(log)) throw Error('Mutation did not reach an assertion: ' + name);
    console.log('KILLED ' + name);
  } finally {
    writeFileSync(file, original);
  }
}
console.log('PASS: ' + mutations.length + ' GitHub collector security mutations killed');
