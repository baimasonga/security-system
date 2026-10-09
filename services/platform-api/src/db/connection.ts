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
    return 'DATABASE_URL is not a valid URL (never printed here): check it starts with postgresql://, has no quotes, spaces or [brackets], and that special characters in the password are percent-encoded';
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

/**
 * The CA certificate used to VERIFY the database server, from `DATABASE_CA_PEM` (the certificate text itself, handy
 * for hosts that only offer environment variables) or `DATABASE_CA_FILE` (a path). Undefined when neither is set.
 * Escaped newlines (`\\n`) are accepted because some dashboards flatten multi-line values.
 */
export function readCaPem(
  env: NodeJS.ProcessEnv,
  readFile: (path: string) => string,
): string | undefined {
  const inline = env['DATABASE_CA_PEM'];
  const file = env['DATABASE_CA_FILE'];
  if (inline && file) throw new Error('set only one of DATABASE_CA_PEM and DATABASE_CA_FILE');
  const pem = inline ? inline.replace(/\\n/g, '\n') : file ? readFile(file) : undefined;
  if (pem !== undefined && !/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(pem))
    throw new Error('the database CA must be a PEM certificate (-----BEGIN CERTIFICATE-----)');
  return pem;
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
  if (o.expectedSchema !== undefined && !f.schema)
    // current_schema() is NULL when no schema on the search path is usable: it does not exist yet, or the role has
    // no USAGE on it. That is "migrations/grants not applied", not a search_path problem.
    throw new Error(
      `the database role cannot use schema "${o.expectedSchema}" yet (it does not exist, or the role has no USAGE on it). Create and grant it first, with the OWNER connection: npm run migrate, then npm run db:grants (see docs/deploy/supabase.md)`,
    );
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

export interface ConnectionTarget {
  host: string;
  port: string;
  user: string;
  database: string;
}

/** The non-secret parts of a database URL (never the password), for logs and error messages. */
export function describeConnectionTarget(databaseUrl: string): ConnectionTarget | undefined {
  try {
    const u = new URL(databaseUrl);
    return {
      host: u.hostname,
      port: u.port || '5432',
      user: decodeURIComponent(u.username),
      database: decodeURIComponent(u.pathname.replace(/^\//, '')),
    };
  } catch {
    return undefined;
  }
}

/**
 * Turns the opaque errors of a failed first connection into an operator-readable cause and fix. Returns undefined for
 * errors it does not recognise (they are re-thrown unchanged). Never includes the password.
 */
export function explainDbError(e: unknown, t: ConnectionTarget | undefined): string | undefined {
  const err = e as { code?: string; message?: string; address?: string };
  const where = t ? `${t.host}:${t.port} as "${t.user}"` : 'the database';
  const code = err?.code;
  const msg = err?.message ?? '';
  if ((code === 'ENETUNREACH' || code === 'EHOSTUNREACH') && (err.address ?? '').includes(':'))
    return `cannot reach ${where} over IPv6 and this host has no IPv6 route. The direct Supabase address (db.<ref>.supabase.co) is IPv6-only: use the Session pooler host (…pooler.supabase.com) with user <role>.<project-ref> instead`;
  if (
    code === 'ENETUNREACH' ||
    code === 'EHOSTUNREACH' ||
    code === 'ETIMEDOUT' ||
    code === 'ECONNREFUSED'
  )
    return `cannot connect to ${where} (${code}): check the host and port, and that the database accepts connections from this host`;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN')
    return `the database host name was not found (${t?.host ?? 'unknown'}): check the host in DATABASE_URL`;
  if (code === '28P01' || /password authentication failed/i.test(msg))
    return `password authentication failed for "${t?.user ?? 'the user'}": the password in DATABASE_URL does not match the database (percent-encode special characters in the password)`;
  if (/tenant or user not found/i.test(msg))
    return `the pooler does not know the user "${t?.user ?? ''}": on the Supabase pooler the user must be <role>.<project-ref> (for example trust_app.abcdefgh)`;
  if (code === '3D000')
    return `database "${t?.database ?? ''}" does not exist on ${t?.host ?? 'the server'}`;
  if (
    /self.signed certificate|unable to verify the first certificate|certificate/i.test(msg) &&
    /cert|SSL|TLS/i.test(`${code} ${msg}`)
  )
    return 'the database TLS certificate is not trusted: set DATABASE_CA_PEM to the database CA certificate (Supabase: Database settings → SSL configuration)';
  return undefined;
}
