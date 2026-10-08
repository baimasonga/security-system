import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Client } from 'pg';
import { assertSchemaName } from './connection.ts';

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
export async function applyMigrations(
  client: Client,
  dir: string,
  opts: { schema?: string | undefined } = {},
): Promise<MigrationResult> {
  if (opts.schema !== undefined) {
    // Everything (tables, functions, the migration ledger) is created inside this schema, not `public`, so a
    // managed platform's auto-generated API never sees it. Session-level: use a direct connection.
    const s = assertSchemaName(opts.schema);
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${s}"`);
    await client.query(`SET search_path TO "${s}"`);
  }
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

/** Startup guard: refuse to serve traffic on a database that is missing (or ahead of) known migrations. */
export async function assertSchemaCurrent(
  db: { query(text: string): Promise<{ rows: Array<{ version: string }> }> },
  dir: string,
): Promise<void> {
  const expected = readdirSync(dir)
    .filter((f) => FILE.test(f))
    .map((f) => f.replace(/\.sql$/, ''))
    .sort();
  let applied: string[];
  try {
    applied = (await db.query('SELECT version FROM schema_migrations ORDER BY version')).rows.map(
      (r) => r.version,
    );
  } catch {
    throw new Error('database schema is not initialised: run `npm run migrate`');
  }
  const missing = expected.filter((v) => !applied.includes(v));
  const unknown = applied.filter((v) => !expected.includes(v));
  if (missing.length)
    throw new Error(
      `database is missing migrations: ${missing.join(', ')} (run \`npm run migrate\`)`,
    );
  if (unknown.length)
    throw new Error(`database has migrations unknown to this build: ${unknown.join(', ')}`);
}

export const MIGRATIONS_DIR = fileURLToPath(new URL('../../migrations', import.meta.url));
