// Deployment-local, read-only preflight. Never sends email or prints credentials/provider errors.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { loadConfig } from '../services/platform-api/src/config.ts';
import { poolSettings } from '../services/platform-api/src/db/connection.ts';
import { incidentEmailReadiness } from './incident-email-readiness.ts';

// Read from stdin to avoid placing an account address in process arguments or shell history.
let pool: pg.Pool | undefined;
try {
  if (process.argv.length !== 2) throw new Error('invalid usage');
  const email = readFileSync(0, 'utf8').trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    throw new Error('invalid input');
  const config = loadConfig(process.env);
  if (config.persistence !== 'postgres' || !config.databaseUrl || !config.dbSchema)
    throw new Error('postgres schema required');
  pool = new pg.Pool({
    ...poolSettings({ databaseUrl: config.databaseUrl, max: 1, caPem: config.databaseCaPem }),
    connectionTimeoutMillis: 10000,
  });
  const db = await pool.connect();
  try {
    await db.query('BEGIN READ ONLY');
    await db.query("SET LOCAL statement_timeout = '5s'");
    const schema = await db.query('SELECT current_schema() AS name');
    if (schema.rows[0]?.name !== config.dbSchema) throw new Error('schema mismatch');
    const result = await db.query(
      `WITH recipient AS (SELECT id, email_verified_at FROM users WHERE email = $1)
       SELECT EXISTS(SELECT 1 FROM recipient) AS account_exists,
         EXISTS(SELECT 1 FROM recipient WHERE email_verified_at IS NOT NULL) AS email_verified,
         (SELECT count(*)::int FROM operations_alert_rules WHERE enabled AND created_by_user_id IN (SELECT id FROM recipient)) AS enabled_rules,
         count(*) FILTER (WHERE state='pending')::int AS pending,
         count(*) FILTER (WHERE state='claimed')::int AS claimed,
         count(*) FILTER (WHERE state='delivered')::int AS delivered,
         count(*) FILTER (WHERE state='failed')::int AS failed
       FROM operations_alert_notifications WHERE recipient_user_id IN (SELECT id FROM recipient)`,
      [email],
    );
    const row = result.rows[0]!;
    const report = incidentEmailReadiness(config, {
      accountExists: row.account_exists,
      emailVerified: row.email_verified,
      enabledRules: row.enabled_rules,
      pending: row.pending,
      claimed: row.claimed,
      delivered: row.delivered,
      failed: row.failed,
    });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.ready_for_controlled_test ? 0 : 1;
  } finally {
    try {
      await db.query('ROLLBACK');
    } finally {
      db.release();
    }
  }
} catch {
  console.error(
    'Incident-email preflight unavailable: check stdin email, runtime configuration, database access and schema. No email sent.',
  );
  process.exitCode = 2;
} finally {
  await pool?.end();
}
