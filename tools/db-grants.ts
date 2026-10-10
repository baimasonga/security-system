// Applies least-privilege grants for the application's database role (ADR-012). Run after every migration.
//   DATABASE_MIGRATE_URL   connection of the schema OWNER (direct)
//   DB_SCHEMA              schema holding the platform's tables
//   APP_DB_ROLE            the application's login role (must already exist; see docs/deploy/supabase.md)
import { readFileSync } from 'node:fs';
import pg from 'pg';
import {
  describeConnectionTarget,
  explainDbError,
  poolSettings,
  readCaPem,
} from '../services/platform-api/src/db/connection.ts';
import { applyAppGrants } from '../services/platform-api/src/db/grants.ts';

const urlVar = process.env['DATABASE_MIGRATE_URL'] ? 'DATABASE_MIGRATE_URL' : 'DATABASE_URL';
const url = process.env[urlVar];
const schema = process.env['DB_SCHEMA'];
const role = process.env['APP_DB_ROLE'];
if (!url || !schema || !role) {
  console.error('DATABASE_MIGRATE_URL, DB_SCHEMA and APP_DB_ROLE are required');
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
  const statements = await applyAppGrants(client, { schema, role });
  console.log(`applied ${statements.length} statements for role "${role}" on schema "${schema}"`);
} catch (e) {
  console.error(`failed: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await client.end();
}
