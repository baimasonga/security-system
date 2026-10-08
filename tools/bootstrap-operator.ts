// Makes an EXISTING user a platform operator (admin). Deliberately not an HTTP endpoint: it is deployment tooling.
//
//   DATABASE_URL=… DB_SCHEMA=trust node tools/bootstrap-operator.ts --email you@example.com --reason "initial operator"
//
// 1. Register the account first through the API (POST /v1/auth/register).
// 2. Run this with the APPLICATION's connection (the least-privilege role is enough). It writes an
//    `operator.bootstrapped` audit event with your reason. Revoke with the same kind of out-of-band step.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { AuthService } from '@trust/auth';
import { systemClock } from '@trust/shared-types';
import { poolSettings } from '../services/platform-api/src/db/connection.ts';
import { PgAuditLog } from '../services/platform-api/src/db/pg-audit-log.ts';
import { PgAuthStore } from '../services/platform-api/src/db/pg-auth-store.ts';

const arg = (name: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const email = arg('email');
const reason = arg('reason');
const url = process.env['DATABASE_URL'];
if (!email || !reason || !url) {
  console.error(
    'usage: DATABASE_URL=… node tools/bootstrap-operator.ts --email <address> --reason "<why>"',
  );
  process.exit(2);
}
const ca = process.env['DATABASE_CA_FILE'];
const pool = new pg.Pool(
  poolSettings({ databaseUrl: url, max: 1, caPem: ca ? readFileSync(ca, 'utf8') : undefined }),
);
try {
  const shards = Number(process.env['AUDIT_CHAIN_SHARDS'] ?? 1);
  const audit = new PgAuditLog(pool, systemClock, { shards });
  const store = new PgAuthStore(pool, systemClock, { auditShards: shards });
  const auth = new AuthService({ store, clock: systemClock, audit });
  await auth.bootstrapPlatformAdmin(email, reason);
  console.log(`OK: ${email.trim().toLowerCase()} is now a platform operator`);
} catch (e) {
  console.error(`failed: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await pool.end();
}
