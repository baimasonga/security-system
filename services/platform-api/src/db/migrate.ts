import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Client } from 'pg';

export interface MigrationResult {
  applied: string[];
  skipped: string[];
}

const FILE = /^(\d{4})_[a-z0-9_]+\.sql$/;

/**
 * Forward-only migrations. Each file runs in its own transaction (the SQL files carry BEGIN/COMMIT).
 * `schema_migrations` records a checksum; a changed file for an already-applied version is an error —
 * history is immutable, fixes ship as a new migration.
 */
export async function applyMigrations(client: Client, dir: string): Promise<MigrationResult> {
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
  // Serialize concurrent deploys.
  await client.query('SELECT pg_advisory_lock(727274)');
  try {
    const files = readdirSync(dir)
      .filter((f) => FILE.test(f))
      .sort();
    const result: MigrationResult = { applied: [], skipped: [] };
    for (const f of files) {
      const version = f.replace(/\.sql$/, '');
      const sql = readFileSync(join(dir, f), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const row = await client.query<{ checksum: string }>(
        'SELECT checksum FROM schema_migrations WHERE version = $1',
        [version],
      );
      if (row.rows[0]) {
        if (row.rows[0].checksum !== checksum)
          throw new Error(`migration ${version} was modified after being applied`);
        result.skipped.push(version);
        continue;
      }
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)', [
          version,
          checksum,
        ]);
      } catch (e) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw e;
      }
      result.applied.push(version);
    }
    return result;
  } finally {
    await client.query('SELECT pg_advisory_unlock(727274)');
  }
}
