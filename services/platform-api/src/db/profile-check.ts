import { SCHEMA_NAME } from './connection.ts';
import type { Queryable } from './pg.ts';
import { API_ROLES } from './grants.ts';

// `npm run db:check`: is this database connection set up the way the Supabase/managed profile (ADR-012) requires?
// Facts are gathered with read-only catalog queries; judgement is a pure function so it can be tested exhaustively.

export interface TablePrivs {
  name: string;
  owner: string;
  select: boolean;
  insert: boolean;
  update: boolean;
  delete: boolean;
  truncate: boolean;
  trigger: boolean;
  references: boolean;
}

export interface ProfileFacts {
  user: string;
  host: string;
  tls: boolean;
  schema: string | null;
  expectedSchema: string | undefined;
  superuser: boolean;
  bypassRls: boolean;
  migrationsCurrent: boolean;
  migrationsDetail: string;
  canCreateInSchema: boolean;
  tables: TablePrivs[];
  /** API roles that exist on this server and what they can reach in the schema. */
  apiRoles: Array<{ role: string; schemaUsage: boolean; tablePrivileges: number }>;
  /** `pgrst.db_schemas` of the API gateway role, when this server has one; null = no gateway role found. */
  exposedSchemas: string[] | null;
}

export type Status = 'pass' | 'fail' | 'warn';
export interface Check {
  id: string;
  status: Status;
  detail: string;
}

const LOCAL = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '']);
const AUDIT_APPEND_ONLY = ['audit_events', 'audit_anchors'];

export function evaluate(f: ProfileFacts): Check[] {
  const out: Check[] = [];
  const add = (id: string, ok: boolean, detail: string, whenNot: Status = 'fail') =>
    out.push({ id, status: ok ? 'pass' : whenNot, detail });

  const local = LOCAL.has(f.host);
  out.push(
    f.tls
      ? { id: 'tls', status: 'pass', detail: 'connection is encrypted' }
      : { id: 'tls', status: local ? 'warn' : 'fail', detail: 'connection is NOT encrypted' },
  );

  if (f.expectedSchema === undefined)
    out.push({
      id: 'schema',
      status: f.schema === 'public' && f.apiRoles.length > 0 ? 'fail' : 'warn',
      detail: `DB_SCHEMA is not set (using "${f.schema ?? ''}"); on a managed platform keep the tables out of "public"`,
    });
  else
    add(
      'schema',
      f.schema === f.expectedSchema && f.expectedSchema !== 'public',
      `current schema "${f.schema ?? ''}", expected "${f.expectedSchema}" (not "public")`,
    );

  add('migrations', f.migrationsCurrent, f.migrationsDetail);
  add(
    'not-superuser',
    !f.superuser,
    f.superuser ? 'the role is a superuser' : 'the role is not a superuser',
  );
  add(
    'bypass-rls',
    !f.bypassRls,
    f.bypassRls ? 'the role bypasses row-level security' : 'the role does not bypass RLS',
    'warn',
  );

  const owned = f.tables.filter((t) => t.owner === f.user);
  add(
    'not-owner',
    owned.length === 0,
    owned.length
      ? `the role owns ${owned.map((t) => t.name).join(', ')} and could disable audit triggers`
      : 'the role owns no tables',
  );

  const bad: string[] = [];
  for (const t of f.tables) {
    if (AUDIT_APPEND_ONLY.includes(t.name) && (t.update || t.delete))
      bad.push(`${t.name}:${t.update ? 'UPDATE' : 'DELETE'}`);
    if (t.name === 'audit_chains' && t.delete) bad.push('audit_chains:DELETE');
    if (t.truncate) bad.push(`${t.name}:TRUNCATE`);
    if (t.trigger) bad.push(`${t.name}:TRIGGER`);
    if (t.references) bad.push(`${t.name}:REFERENCES`);
  }
  add(
    'audit-append-only',
    bad.length === 0,
    bad.length
      ? `forbidden privileges: ${bad.join(', ')}`
      : 'no rewrite/truncate/trigger privileges on audit tables or elsewhere',
  );
  add(
    'no-ddl',
    !f.canCreateInSchema,
    f.canCreateInSchema
      ? 'the role can create objects in the schema'
      : 'the role cannot create objects in the schema',
  );

  const unreachable = f.tables.filter((t) => !t.select).map((t) => t.name);
  add(
    'table-coverage',
    f.tables.length > 0 && unreachable.length === 0,
    f.tables.length === 0
      ? 'no tables are visible to the role in the schema (wrong schema, or no USAGE/SELECT: run npm run db:grants)'
      : unreachable.length
        ? `no access to: ${unreachable.join(', ')} (run npm run db:grants after migrating)`
        : 'the role can read every table',
  );

  const exposedRoles = f.apiRoles.filter((r) => r.schemaUsage || r.tablePrivileges > 0);
  add(
    'api-roles-locked-out',
    exposedRoles.length === 0,
    exposedRoles.length
      ? `${exposedRoles.map((r) => r.role).join(', ')} can reach the schema (run npm run db:grants)`
      : `${f.apiRoles.length ? f.apiRoles.map((r) => r.role).join(', ') : 'no API roles'}: no access`,
  );

  if (f.exposedSchemas === null)
    out.push({
      id: 'api-not-exposed',
      status: 'pass',
      detail: 'no API gateway configuration found on this server',
    });
  else
    add(
      'api-not-exposed',
      !(f.schema && f.exposedSchemas.includes(f.schema)),
      `schemas exposed by the API gateway: ${f.exposedSchemas.join(', ') || '(none)'}`,
    );
  return out;
}

export async function gatherFacts(
  db: Queryable,
  o: { host: string; expectedSchema: string | undefined; migrationsDir: string },
): Promise<ProfileFacts> {
  const { assertSchemaCurrent } = await import('./migrate.ts');
  const me = (
    await db.query(
      `SELECT current_user AS usr, current_schema() AS schema, r.rolsuper, r.rolbypassrls,
              coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS tls
         FROM pg_roles r WHERE r.rolname = current_user`,
    )
  ).rows[0]!;
  // `current_schema()` is NULL for a schema the role cannot use, so judge the CONFIGURED schema when there is one.
  const schema = (o.expectedSchema ?? (me.schema as string | null)) as string | null;

  let migrationsCurrent = true;
  let migrationsDetail = 'all migrations applied';
  try {
    await assertSchemaCurrent(db as never, o.migrationsDir);
  } catch (e) {
    migrationsCurrent = false;
    migrationsDetail = (e as Error).message;
  }

  const tables = (
    await db.query(
      `SELECT t.tablename AS name, t.tableowner AS owner,
              has_table_privilege(current_user, c.oid, 'SELECT') AS sel,
              has_table_privilege(current_user, c.oid, 'INSERT') AS ins,
              has_table_privilege(current_user, c.oid, 'UPDATE') AS upd,
              has_table_privilege(current_user, c.oid, 'DELETE') AS del,
              has_table_privilege(current_user, c.oid, 'TRUNCATE') AS trunc,
              has_table_privilege(current_user, c.oid, 'TRIGGER') AS trig,
              has_table_privilege(current_user, c.oid, 'REFERENCES') AS ref
         FROM pg_tables t JOIN pg_class c ON c.relname = t.tablename
         JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.schemaname
        WHERE t.schemaname = $1 ORDER BY t.tablename`,
      [schema],
    )
  ).rows.map((r): TablePrivs => ({
    name: r.name,
    owner: r.owner,
    select: r.sel,
    insert: r.ins,
    update: r.upd,
    delete: r.del,
    truncate: r.trunc,
    trigger: r.trig,
    references: r.ref,
  }));

  const canCreate = schema
    ? ((
        await db.query(
          "SELECT CASE WHEN to_regnamespace($1) IS NULL THEN false ELSE has_schema_privilege(current_user, $1, 'CREATE') END AS c",
          [schema],
        )
      ).rows[0]!.c as boolean)
    : false;

  const apiRoles: ProfileFacts['apiRoles'] = [];
  for (const role of API_ROLES) {
    const exists =
      (await db.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role])).rows.length > 0;
    if (!exists || !schema) continue;
    const r = (
      await db.query(
        `SELECT CASE WHEN to_regnamespace($2) IS NULL THEN false ELSE has_schema_privilege($1, $2, 'USAGE') END AS usage,
                (SELECT count(*)::int FROM pg_tables t JOIN pg_class c ON c.relname = t.tablename
                   JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.schemaname
                  WHERE t.schemaname = $2
                    AND (has_table_privilege($1, c.oid, 'SELECT') OR has_table_privilege($1, c.oid, 'INSERT')
                      OR has_table_privilege($1, c.oid, 'UPDATE') OR has_table_privilege($1, c.oid, 'DELETE'))) AS privs`,
        [role, schema],
      )
    ).rows[0]!;
    apiRoles.push({ role, schemaUsage: r.usage as boolean, tablePrivileges: r.privs as number });
  }

  let exposedSchemas: string[] | null = null;
  const gw = (await db.query("SELECT rolconfig FROM pg_roles WHERE rolname = 'authenticator'"))
    .rows[0];
  if (gw) {
    const cfg = ((gw.rolconfig as string[] | null) ?? []).find((c) =>
      c.startsWith('pgrst.db_schemas='),
    );
    exposedSchemas = cfg
      ? cfg
          .slice('pgrst.db_schemas='.length)
          .split(',')
          .map((s) => s.trim())
          .filter((s) => SCHEMA_NAME.test(s))
      : [];
  }

  return {
    user: me.usr as string,
    host: o.host,
    tls: me.tls as boolean,
    schema: me.schema as string | null,
    expectedSchema: o.expectedSchema,
    superuser: me.rolsuper as boolean,
    bypassRls: me.rolbypassrls as boolean,
    migrationsCurrent,
    migrationsDetail,
    canCreateInSchema: canCreate,
    tables,
    apiRoles,
    exposedSchemas,
  };
}
