// Deliberately break one control at a time; restore exact source bytes after every run.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const service = 'packages/operations/src/posture.ts';
const tests = [
  'packages/operations/test/posture.test.ts',
  'packages/operations/test/posture-normalizer.test.ts',
  'services/platform-api/test/operations-posture.test.ts',
];
const mutations = [
  ['flag', service, 'if (!this.#d.enabled()) throw missing();', 'if (false) throw missing();'],
  ['transaction-authority', service, 'await authorize(tx.authority ?? this.#d.authority);', ''],
  [
    'session',
    service,
    'if (!(await authority.sessionActive?.(p, this.#d.clock.now())))',
    'if (false)',
  ],
  ['freeze', service, 'await authority.assertWritable(scope.orgId);', ''],
  [
    'future-evidence',
    service,
    'completed > +now || completed < +now - 30 * 86400000',
    'completed < +now - 30 * 86400000',
  ],
  ['report-cap', service, 'records.length >= 100', 'records.length > 100'],
  [
    'restore-checks',
    service,
    "[r.integrity_check, r.application_check, r.audit_check].every((v) => v === 'passed')",
    'true',
  ],
  ['finding-version', service, 'if (old.version !== b.expected_version) throw conflict();', ''],
  ['assignee', service, 'b.assignee_user_id &&', 'false && b.assignee_user_id &&'],
  ['provenance', service, 'independentlyVerified: false', 'independentlyVerified: true', true],
  ['audit', service, 'await tx.audit.append(', 'await Promise.resolve(', true],
  [
    'monotonic-assessment',
    service,
    'return fn(tx, await tx.observeHealthTime(scope.orgId, this.#d.clock.now()));',
    'return fn(tx, this.#d.clock.now());',
  ],
  [
    'member-grant',
    'packages/auth/src/rbac.ts',
    '  member: [',
    "  member: [\n    'ops:read', 'ops:manage_security',",
  ],
  [
    'raw-export',
    'tools/normalize-security-export.ts',
    'return result.data;',
    'return { ...result.data, raw };',
  ],
  [
    'evidence-immutability',
    'services/platform-api/migrations/0024_operations_posture.sql',
    'CREATE TRIGGER operations_security_immutable BEFORE UPDATE OR DELETE ON operations_security_evidence FOR EACH ROW EXECUTE FUNCTION operations_security_immutable();',
    '-- trigger removed',
    false,
    'security evidence is immutable',
  ],
  [
    'finding-identity',
    'services/platform-api/migrations/0024_operations_posture.sql',
    'IF ROW(NEW.id',
    'IF false AND ROW(NEW.id',
    false,
    'keeps posture snapshots',
  ],
];
mkdirSync('/tmp/posture-mutations', { recursive: true });
for (const [name, file, needle, replacement, all, dbTest] of mutations) {
  const original = readFileSync(file);
  const text = original.toString();
  if (!text.includes(needle)) throw Error('Missing mutation anchor: ' + name);
  try {
    writeFileSync(
      file,
      all ? text.replaceAll(needle, replacement) : text.replace(needle, replacement),
    );
    const args = [
      'vitest',
      'run',
      '--project',
      dbTest ? 'db' : 'unit',
      ...(dbTest
        ? ['services/platform-api/test/operations-store.db.test.ts', '-t', dbTest]
        : tests),
    ];
    const r = spawnSync('npx', args, { encoding: 'utf8', timeout: 90000, env: process.env });
    const log = (r.stdout ?? '') + (r.stderr ?? '');
    writeFileSync('/tmp/posture-mutations/' + name + '.log', log);
    if (r.status === 0) throw Error('Mutation survived: ' + name);
    if (!/FAIL\s/.test(log)) throw Error('Mutation did not reach an assertion: ' + name);
    process.stdout.write('KILLED ' + name + '\n');
  } finally {
    writeFileSync(file, original);
  }
}
process.stdout.write('PASS: ' + mutations.length + ' posture security mutations killed\n');
