import type { Queryable } from './pg.ts';

// Connection hygiene for managed PostgreSQL (ADR-012): TLS, schema, and what the application's role may do.

export const SCHEMA_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

/** Throws unless `name` is a plain lowercase identifier (it is interpolated into DDL, so be strict). */
export function assertSchemaName(name: string): string {
  if (!SCHEMA_NAME.test(name)) throw new Error('invalid schema name');
  return name;
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1', '']);

/**
 * Returns a reason when the URL would send credentials and data over an unencrypted or unauthenticated-server
 * channel to a non-local host, otherwise undefined. `sslmode=require|verify-ca|verify-full` (or `ssl=true`) is
 * accepted; with `DATABASE_CA_FILE` the connection is verified against that CA regardless.
 */
export function tlsProblem(databaseUrl: string): string | undefined {
  let u: URL;
  try {
    u = new URL(databaseUrl);
  } catch {
    return 'DATABASE_URL is not a valid URL';
  }
  const host = u.hostname;
  const params = u.searchParams;
  // A unix-socket host is a directory path (e.g. ?host=/var/run/postgresql or empty host).
  const socket = (params.get('host') ?? '').startsWith('/');
  if (LOCAL_HOSTS.has(host) || socket) return undefined;
  const mode = params.get('sslmode');
  const ok =
    mode === 'require' ||
    mode === 'verify-ca' ||
    mode === 'verify-full' ||
    params.get('ssl') === 'true';
  return ok
    ? undefined
    : 'DATABASE_URL must require TLS (add ?sslmode=require or verify-full) for a non-local database';
}

export interface PoolSettings {
  connectionString: string;
  max: number;
  ssl?: { ca: string; rejectUnauthorized: true };
}

/**
 * Pool settings. With a CA certificate the server is verified against it; because `pg` lets connection-string
 * parameters override the `ssl` object, the TLS-related parameters are removed from the string in that case.
 * No startup parameters (`options=-c …`) are sent: transaction-mode poolers reject them, and the schema and
 * timeouts are set on the database ROLE instead (see docs/deploy/supabase.md).
 */
export function poolSettings(opts: {
  databaseUrl: string;
  max: number;
  caPem?: string | undefined;
}): PoolSettings {
  if (!opts.caPem) return { connectionString: opts.databaseUrl, max: opts.max };
  const u = new URL(opts.databaseUrl);
  for (const p of ['sslmode', 'ssl', 'sslrootcert', 'sslcert', 'sslkey']) u.searchParams.delete(p);
  return {
    connectionString: u.toString(),
    max: opts.max,
    ssl: { ca: opts.caPem, rejectUnauthorized: true },
  };
}

export interface RoleFacts {
  user: string;
  schema: string | null;
  superuser: boolean;
  bypassRls: boolean;
  /** Tables in the schema owned by the current role (an owner can disable triggers and rewrite history). */
  ownedTables: number;
}

export async function gatherRoleFacts(db: Queryable): Promise<RoleFacts> {
  const r = await db.query(
    `SELECT current_user AS usr, current_schema() AS schema, r.rolsuper, r.rolbypassrls,
            (SELECT count(*)::int FROM pg_tables t WHERE t.schemaname = current_schema() AND t.tableowner = current_user) AS owned
       FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const row = r.rows[0]!;
  return {
    user: row.usr as string,
    schema: row.schema as string | null,
    superuser: row.rolsuper as boolean,
    bypassRls: row.rolbypassrls as boolean,
    ownedTables: row.owned as number,
  };
}

/**
 * Startup judgement of the application's database role. A superuser connection defeats the audit log's
 * database-level protections (R-13) and every grant, so production refuses it unless explicitly accepted.
 * Returns the warnings to log; throws on a refusal.
 */
export function judgeRole(
  f: RoleFacts,
  o: { production: boolean; expectedSchema: string | undefined; allowSuperuser: boolean },
): string[] {
  if (o.expectedSchema !== undefined && f.schema !== o.expectedSchema)
    throw new Error(
      `connected with schema "${f.schema ?? ''}" but DB_SCHEMA=${o.expectedSchema}: set the role's search_path (ALTER ROLE … SET search_path = ${o.expectedSchema})`,
    );
  const warnings: string[] = [];
  if (f.superuser) {
    if (o.production && !o.allowSuperuser)
      throw new Error(
        'the application connects as a database superuser; use a least-privilege role (npm run db:grants) or set DB_ALLOW_SUPERUSER=true to accept that',
      );
    warnings.push('application role is a database superuser');
  }
  if (f.ownedTables > 0)
    warnings.push(
      `application role owns ${f.ownedTables} table(s) and could disable the audit triggers`,
    );
  if (f.bypassRls) warnings.push('application role bypasses row-level security');
  return warnings;
}
