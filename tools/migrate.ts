// Applies SQL migrations.
//   DATABASE_MIGRATE_URL (or DATABASE_URL)  connection of the schema OWNER, direct (not a transaction-mode pooler)
//   DB_SCHEMA                               optional: create and migrate inside this schema instead of the default
// Usage: DATABASE_MIGRATE_URL=postgres://owner@host/db DB_SCHEMA=trust node tools/migrate.ts
import { readFileSync } from 'node:fs';
import pg from 'pg';
import {
  describeConnectionTarget,
  explainDbError,
  poolSettings,
  readCaPem,
} from '../services/platform-api/src/db/connection.ts';
import { MIGRATIONS_DIR, applyMigrations } from '../services/platform-api/src/db/migrate.ts';

const urlVar = process.env['DATABASE_MIGRATE_URL'] ? 'DATABASE_MIGRATE_URL' : 'DATABASE_URL';
const url = process.env[urlVar];
if (!url) {
  console.error('DATABASE_MIGRATE_URL (or DATABASE_URL) is required');
  process.exit(2);
}
const ca = readCaPem(process.env, (p) => readFileSync(p, 'utf8'));
const { connectionString, ssl } = poolSettings({ databaseUrl: url, max: 1, caPem: ca });
const client = new pg.Client(ssl ? { connectionString, ssl } : { connectionString });
try {
  await client.connect();
} catch (e) {
  const hint = explainDbError(e, describeConnectionTarget(url), urlVar);
  console.error(`could not connect: ${hint ?? (e as Error).message}`);
  process.exit(1);
}
try {
  const schema = process.env['DB_SCHEMA'];
  const r = await applyMigrations(client, MIGRATIONS_DIR, schema ? { schema } : {});
  console.log(
    `applied: ${r.applied.join(', ') || '(none)'}; already applied: ${r.skipped.join(', ') || '(none)'}`,
  );
} finally {
  await client.end();
}
