import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Read-only restore acceptance: compare identities AND exact SQL checksums, never a hardcoded migration count. */
export async function verifyRestoredMigrations(
  db: { query(sql: string): Promise<{ rows: Array<{ version: string; checksum: string }> }> },
  dir: string,
): Promise<number> {
  const expected = readdirSync(dir)
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
    .sort()
    .map((name) => ({
      version: name.replace(/\.sql$/, ''),
      checksum: createHash('sha256')
        .update(readFileSync(join(dir, name)))
        .digest('hex'),
    }));
  assert.ok(expected.length > 0, 'migration source must not be empty');
  const actual = (
    await db.query('SELECT version, checksum FROM schema_migrations ORDER BY version')
  ).rows;
  assert.deepEqual(
    actual,
    expected,
    'restored migration identities or checksums differ from this build',
  );
  return expected.length;
}
