// Applies SQL migrations. Usage: DATABASE_URL=postgres://… node tools/migrate.ts
import pg from 'pg';
import { MIGRATIONS_DIR, applyMigrations } from '../services/platform-api/src/db/migrate.ts';

const url = process.env['DATABASE_URL'];
if (!url) {
  console.error('DATABASE_URL is required');
  process.exit(2);
}
const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  const r = await applyMigrations(client, MIGRATIONS_DIR);
  console.log(
    `applied: ${r.applied.join(', ') || '(none)'}; already applied: ${r.skipped.join(', ') || '(none)'}`,
  );
} finally {
  await client.end();
}
