// Prove guide selection and recovery-safety assertions reject deliberately broken instructions.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const file = 'services/platform-api/src/web/operations.mjs';
const original = readFileSync(file, 'utf8');
const mutations = [
  ['inherited-guide', '!Object.hasOwn(responseGuides, code)', 'false'],
  ['scanner-bypass', 'Never disable scanning', 'Disable scanning'],
  ['confirmation-bypass', 'Keep email confirmation enabled', 'Disable email confirmation'],
  ['backup-confidence', 'Do not delete', 'Delete'],
];
mkdirSync('/tmp/response-guide-mutations', { recursive: true });
for (const [name, needle, replacement] of mutations) {
  if (!original.includes(needle)) throw Error('Mutation anchor missing: ' + name);
  try {
    writeFileSync(file, original.replace(needle, replacement));
    const result = spawnSync(
      'npx',
      ['vitest', 'run', '--project', 'unit', 'services/platform-api/test/response-guides.test.mjs'],
      { encoding: 'utf8', timeout: 30000 },
    );
    const log = (result.stdout ?? '') + (result.stderr ?? '');
    writeFileSync('/tmp/response-guide-mutations/' + name + '.log', log);
    if (result.status === 0 || !/FAIL\s/.test(log))
      throw Error('Mutation did not fail an assertion: ' + name);
    console.log('KILLED ' + name);
  } finally {
    writeFileSync(file, original);
  }
}
