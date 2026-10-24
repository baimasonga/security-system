import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { verifyRestoredMigrations } from '../../../tools/restore-migrations.ts';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'restore-ledger-'));
  dirs.push(dir);
  const sql = 'CREATE TABLE restored_fixture(id text);\n';
  writeFileSync(join(dir, '0001_fixture.sql'), sql);
  writeFileSync(join(dir, 'README.md'), 'not a migration');
  return {
    dir,
    rows: [{ version: '0001_fixture', checksum: createHash('sha256').update(sql).digest('hex') }],
  };
}
it('accepts the exact restored source ledger and automatically includes new migrations', async () => {
  const { dir, rows } = fixture();
  expect(await verifyRestoredMigrations({ query: async () => ({ rows }) }, dir)).toBe(1);
  const sql = 'SELECT 1;\n';
  writeFileSync(join(dir, '0002_forward.sql'), sql);
  rows.push({ version: '0002_forward', checksum: createHash('sha256').update(sql).digest('hex') });
  expect(await verifyRestoredMigrations({ query: async () => ({ rows }) }, dir)).toBe(2);
});
it.each(['missing', 'wrong-version', 'wrong-checksum', 'duplicate', 'unexpected'])(
  'rejects a restored ledger with %s even when the count could match',
  async (kind) => {
    const { dir, rows } = fixture();
    if (kind === 'missing') rows.pop();
    if (kind === 'wrong-version') rows[0]!.version = '0001_unrelated';
    if (kind === 'wrong-checksum') rows[0]!.checksum = '0'.repeat(64);
    if (kind === 'duplicate') rows.push({ ...rows[0]! });
    if (kind === 'unexpected') rows.push({ version: '9999_unknown', checksum: 'a'.repeat(64) });
    await expect(
      verifyRestoredMigrations({ query: async () => ({ rows }) }, dir),
    ).rejects.toThrow();
  },
);
it('refuses an empty migration source rather than accepting a missing ledger', async () => {
  const { dir } = fixture();
  rmSync(join(dir, '0001_fixture.sql'));
  await expect(
    verifyRestoredMigrations({ query: async () => ({ rows: [] }) }, dir),
  ).rejects.toThrow();
});
