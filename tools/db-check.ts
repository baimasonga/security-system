// Verifies that THIS connection (the application's DATABASE_URL) matches the managed-database profile (ADR-012):
// encrypted, tables in a private schema, no superuser/owner/DDL rights, audit tables append-only for the role,
// API roles locked out. Exit 0 = no failures (warnings allowed), 1 = at least one failure, 2 = usage.
import pg from 'pg';
import { poolSettings, readCaPem } from '../services/platform-api/src/db/connection.ts';
import { MIGRATIONS_DIR } from '../services/platform-api/src/db/migrate.ts';
import { evaluate, gatherFacts } from '../services/platform-api/src/db/profile-check.ts';
import { readFileSync } from 'node:fs';

const url = process.env['DATABASE_URL'];
if (!url) {
  console.error('DATABASE_URL (the application connection) is required');
  process.exit(2);
}
const ca = readCaPem(process.env, (p) => readFileSync(p, 'utf8'));
const pool = new pg.Pool(poolSettings({ databaseUrl: url, max: 1, caPem: ca }));
try {
  const facts = await gatherFacts(pool, {
    host: new URL(url).hostname,
    expectedSchema: process.env['DB_SCHEMA'],
    migrationsDir: MIGRATIONS_DIR,
  });
  const checks = evaluate(facts);
  for (const c of checks)
    console.log(`${c.status.toUpperCase().padEnd(4)}  ${c.id.padEnd(22)} ${c.detail}`);
  const failed = checks.filter((c) => c.status === 'fail').length;
  const warned = checks.filter((c) => c.status === 'warn').length;
  console.log(
    failed ? `\n${failed} check(s) FAILED` : `\nOK${warned ? ` (${warned} warning(s))` : ''}`,
  );
  process.exitCode = failed ? 1 : 0;
} finally {
  await pool.end();
}
