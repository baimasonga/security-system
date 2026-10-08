// Applies least-privilege grants for the application's database role (ADR-012). Run after every migration.
//   DATABASE_MIGRATE_URL   connection of the schema OWNER (direct)
//   DB_SCHEMA              schema holding the platform's tables
//   APP_DB_ROLE            the application's login role (must already exist; see docs/deploy/supabase.md)
import pg from 'pg';
import { applyAppGrants } from '../services/platform-api/src/db/grants.ts';

const url = process.env['DATABASE_MIGRATE_URL'] ?? process.env['DATABASE_URL'];
const schema = process.env['DB_SCHEMA'];
const role = process.env['APP_DB_ROLE'];
if (!url || !schema || !role) {
  console.error('DATABASE_MIGRATE_URL, DB_SCHEMA and APP_DB_ROLE are required');
  process.exit(2);
}
const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  const statements = await applyAppGrants(client, { schema, role });
  console.log(`applied ${statements.length} statements for role "${role}" on schema "${schema}"`);
} catch (e) {
  console.error(`failed: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await client.end();
}
