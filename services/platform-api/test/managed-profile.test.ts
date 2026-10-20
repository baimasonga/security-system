import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';
import {
  assertSchemaName,
  describeConnectionTarget,
  explainDbError,
  judgeRole,
  poolSettings,
  readCaPem,
  tlsProblem,
  type RoleFacts,
} from '../src/db/connection.ts';
import { API_ROLES, TABLE_PRIVILEGES, planGrants } from '../src/db/grants.ts';
import { evaluate, type ProfileFacts, type TablePrivs } from '../src/db/profile-check.ts';

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;

describe('tlsProblem', () => {
  it('requires TLS for remote databases, allows loopback and unix sockets', () => {
    expect(
      tlsProblem('postgres://u:p@db.example.com:5432/postgres?sslmode=require'),
    ).toBeUndefined();
    expect(
      tlsProblem('postgres://u:p@db.example.com/postgres?sslmode=verify-full'),
    ).toBeUndefined();
    expect(tlsProblem('postgres://u:p@db.example.com/postgres?ssl=true')).toBeUndefined();
    expect(tlsProblem('postgres://u:p@localhost/db')).toBeUndefined();
    expect(tlsProblem('postgres://u:p@127.0.0.1:5432/db')).toBeUndefined();
    expect(tlsProblem('postgres:///db?host=/var/run/postgresql')).toBeUndefined();
    for (const bad of [
      'postgres://u:p@db.example.com/postgres',
      'postgres://u:p@db.example.com/postgres?sslmode=disable',
      'postgres://u:p@db.example.com/postgres?sslmode=prefer',
      'postgres://u:p@db.example.com/postgres?sslmode=allow',
      'not a url',
    ])
      expect(tlsProblem(bad), bad).toMatch(/TLS|valid URL/);
  });
});

describe('poolSettings', () => {
  it('sends no startup options, and verifies against the CA when one is configured', () => {
    const plain = poolSettings({ databaseUrl: 'postgres://u:p@h/db?sslmode=require', max: 7 });
    expect(plain).toEqual({ connectionString: 'postgres://u:p@h/db?sslmode=require', max: 7 });
    expect(JSON.stringify(plain)).not.toContain('options');

    const ca = poolSettings({
      databaseUrl: 'postgres://u:p@h/db?sslmode=require&application_name=x',
      max: 3,
      caPem: 'PEM',
    });
    expect(ca.ssl).toEqual({ ca: 'PEM', rejectUnauthorized: true });
    expect(ca.connectionString).not.toMatch(/sslmode|ssl=|sslrootcert/); // pg lets URL parameters override `ssl`
    expect(ca.connectionString).toContain('application_name=x');
  });
});

describe('schema names', () => {
  it('accepts plain identifiers only (they end up in DDL)', () => {
    expect(assertSchemaName('trust')).toBe('trust');
    expect(assertSchemaName('trust_2')).toBe('trust_2');
    for (const bad of ['', 'Trust', 'a-b', 'a;drop table x', 'a"b', '1abc', 'x'.repeat(64), 'a b'])
      expect(() => assertSchemaName(bad), bad).toThrow(/invalid schema name/);
  });
});

describe('judgeRole', () => {
  const ok: RoleFacts = {
    user: 'app',
    schema: 'trust',
    superuser: false,
    bypassRls: false,
    ownedTables: 0,
  };
  const o = {
    production: true,
    expectedSchema: 'trust' as string | undefined,
    allowSuperuser: false,
  };
  it('accepts a least-privilege role', () => expect(judgeRole(ok, o)).toEqual([]));
  it('explains a missing or unusable schema (not migrated / no USAGE)', () =>
    expect(() => judgeRole({ ...ok, schema: null }, o)).toThrow(/cannot use schema.*migrate/s));
  it('refuses the wrong schema', () =>
    expect(() => judgeRole({ ...ok, schema: 'public' }, o)).toThrow(/search_path/));
  it('refuses a superuser in production unless accepted; warns otherwise', () => {
    const su = { ...ok, superuser: true };
    expect(() => judgeRole(su, o)).toThrow(/superuser/);
    expect(judgeRole(su, { ...o, allowSuperuser: true }).join()).toMatch(/superuser/);
    expect(judgeRole(su, { ...o, production: false }).join()).toMatch(/superuser/);
  });
  it('warns about ownership and RLS bypass', () => {
    const w = judgeRole({ ...ok, ownedTables: 3, bypassRls: true }, o).join(' ');
    expect(w).toMatch(/owns 3/);
    expect(w).toMatch(/row-level security/);
  });
});

describe('planGrants', () => {
  const tables = Object.keys(TABLE_PRIVILEGES);
  it('grants exactly the policy, never rewrite rights on evidence, and locks the API roles out', () => {
    const sql = planGrants({
      schema: 'trust',
      role: 'trust_app',
      tables,
      existingRoles: ['anon', 'authenticated', 'service_role', 'postgres'],
    });
    const grant = (t: string) => sql.find((s) => s.startsWith('GRANT') && s.includes(`."${t}"`));
    expect(grant('audit_events')).toBe(
      'GRANT SELECT, INSERT ON TABLE "trust"."audit_events" TO "trust_app"',
    );
    expect(grant('audit_anchors')).toBe(
      'GRANT SELECT, INSERT ON TABLE "trust"."audit_anchors" TO "trust_app"',
    );
    expect(grant('audit_chains')).not.toMatch(/DELETE/);
    expect(grant('licenses')).toContain('UPDATE'); // FOR UPDATE row locks need it
    expect(sql.join('\n')).not.toMatch(/TRUNCATE|TRIGGER|REFERENCES|ALL PRIVILEGES|CREATE ON/);
    expect(sql).toContain('GRANT USAGE ON SCHEMA "trust" TO "trust_app"');
    for (const r of API_ROLES) expect(sql).toContain(`REVOKE ALL ON SCHEMA "trust" FROM "${r}"`);
    // revokes come before grants so a previously over-granted role is narrowed, not just widened
    expect(sql.findIndex((s) => s.startsWith('REVOKE ALL ON ALL TABLES'))).toBeLessThan(
      sql.findIndex((s) => s.startsWith('GRANT SELECT')),
    );
  });
  it('only touches API roles that exist, and fails closed on an unlisted table or a bad identifier', () => {
    const sql = planGrants({ schema: 'trust', role: 'app', tables, existingRoles: [] });
    expect(sql.join('\n')).not.toMatch(/"anon"/);
    expect(() =>
      planGrants({
        schema: 'trust',
        role: 'app',
        tables: [...tables, 'brand_new_table'],
        existingRoles: [],
      }),
    ).toThrow(/brand_new_table/);
    expect(() => planGrants({ schema: 'tr"ust', role: 'app', tables, existingRoles: [] })).toThrow(
      /invalid schema name/,
    );
    expect(() => planGrants({ schema: 'trust', role: 'app;x', tables, existingRoles: [] })).toThrow(
      /invalid schema name/,
    );
  });
});

describe('evaluate (db:check judgement)', () => {
  const t = (name: string, over: Partial<TablePrivs> = {}): TablePrivs => ({
    name,
    owner: 'owner_role',
    select: true,
    insert: true,
    update: true,
    delete: false,
    truncate: false,
    trigger: false,
    references: false,
    ...over,
  });
  const good: ProfileFacts = {
    user: 'trust_app',
    host: 'db.example.com',
    tls: true,
    schema: 'trust',
    expectedSchema: 'trust',
    superuser: false,
    bypassRls: false,
    migrationsCurrent: true,
    migrationsDetail: 'ok',
    canCreateInSchema: false,
    tables: [
      t('users'),
      t('audit_events', { update: false }),
      t('audit_anchors', { update: false }),
      t('audit_chains'),
    ],
    apiRoles: [{ role: 'anon', schemaUsage: false, tablePrivileges: 0 }],
    exposedSchemas: ['public'],
  };
  const fails = (f: ProfileFacts) =>
    evaluate(f)
      .filter((c) => c.status === 'fail')
      .map((c) => c.id);

  it('passes a correctly configured connection', () => expect(fails(good)).toEqual([]));
  it.each(['insert', 'update'] as const)(
    'fails when the incident table lacks required %s rights',
    (field) => {
      expect(
        fails({ ...good, tables: [...good.tables, t('operations_incidents', { [field]: false })] }),
      ).toContain('required-grants');
    },
  );

  it.each([
    ['unencrypted remote', { tls: false }, 'tls'],
    ['superuser', { superuser: true }, 'not-superuser'],
    ['owner of tables', { tables: [t('users', { owner: 'trust_app' })] }, 'not-owner'],
    ['audit UPDATE', { tables: [t('audit_events', { update: true })] }, 'audit-append-only'],
    [
      'audit DELETE',
      { tables: [t('audit_events', { update: false, delete: true })] },
      'audit-append-only',
    ],
    ['anchors UPDATE', { tables: [t('audit_anchors', { update: true })] }, 'audit-append-only'],
    ['chain head DELETE', { tables: [t('audit_chains', { delete: true })] }, 'audit-append-only'],
    ['TRUNCATE anywhere', { tables: [t('users', { truncate: true })] }, 'audit-append-only'],
    ['TRIGGER anywhere', { tables: [t('users', { trigger: true })] }, 'audit-append-only'],
    ['DDL in schema', { canCreateInSchema: true }, 'no-ddl'],
    ['no tables visible', { tables: [] }, 'table-coverage'],
    ['unreadable table', { tables: [t('users', { select: false })] }, 'table-coverage'],
    [
      'API role with usage',
      { apiRoles: [{ role: 'anon', schemaUsage: true, tablePrivileges: 0 }] },
      'api-roles-locked-out',
    ],
    [
      'API role with table rights',
      { apiRoles: [{ role: 'authenticated', schemaUsage: false, tablePrivileges: 4 }] },
      'api-roles-locked-out',
    ],
    ['schema exposed by the gateway', { exposedSchemas: ['public', 'trust'] }, 'api-not-exposed'],
    ['wrong schema', { schema: 'other' }, 'schema'],
    ['public schema', { schema: 'public', expectedSchema: 'public' }, 'schema'],
    ['migrations behind', { migrationsCurrent: false }, 'migrations'],
  ] as Array<[string, Partial<ProfileFacts>, string]>)('fails: %s', (_n, over, id) => {
    expect(fails({ ...good, ...over })).toContain(id);
  });

  it('warns (not fails) about plain TLS-less loopback and RLS bypass; schema unset on a non-public default is a warning', () => {
    const cs = evaluate({
      ...good,
      host: '127.0.0.1',
      tls: false,
      bypassRls: true,
      expectedSchema: undefined,
    });
    expect(cs.find((c) => c.id === 'tls')?.status).toBe('warn');
    expect(cs.find((c) => c.id === 'bypass-rls')?.status).toBe('warn');
    expect(cs.find((c) => c.id === 'schema')?.status).toBe('warn');
    expect(cs.filter((c) => c.status === 'fail')).toEqual([]);
    expect(fails({ ...good, expectedSchema: undefined, schema: 'public' })).toContain('schema'); // public + API roles present
  });
});

describe('configuration', () => {
  const prod = {
    NODE_ENV: 'production',
    LICENSE_KEY_PEPPER: 'x'.repeat(40),
    PSEUDONYM_KEY: 'x'.repeat(40),
    LICENSE_SIGNING_KEY_PEM: 'pem',
    AUDIT_ANCHOR_DISABLED: 'true',
  };
  it('production refuses a remote database URL without TLS unless the transport risk is accepted or a CA is configured', () => {
    const url = 'postgres://u:p@db.example.com/postgres';
    expect(() => loadConfig(env({ ...prod, DATABASE_URL: url }))).toThrow(/TLS/);
    expect(loadConfig(env({ ...prod, DATABASE_URL: `${url}?sslmode=require` })).env).toBe(
      'production',
    );
    expect(
      loadConfig(env({ ...prod, DATABASE_URL: url, DATABASE_INSECURE_TRANSPORT: 'true' })).env,
    ).toBe('production');
    expect(loadConfig(env({ ...prod, DATABASE_URL: 'postgres://u:p@localhost/db' })).env).toBe(
      'production',
    );
    // development is not blocked
    expect(loadConfig(env({ PERSISTENCE: 'postgres', DATABASE_URL: url })).persistence).toBe(
      'postgres',
    );
  });

  it('validates DB_SCHEMA and reads the CA file', async () => {
    expect(loadConfig(env({ DB_SCHEMA: 'trust' })).dbSchema).toBe('trust');
    expect(loadConfig(env({})).dbSchema).toBeUndefined();
    for (const bad of ['Trust', 'a;b', 'public schema', ''])
      expect(() => loadConfig(env({ DB_SCHEMA: bad })), bad).toThrow(/DB_SCHEMA/);
    const { writeFileSync, mkdtempSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const f = join(mkdtempSync(join(tmpdir(), 'ca-')), 'ca.pem');
    writeFileSync(f, '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n');
    const withCa = loadConfig(
      env({ ...prod, DATABASE_URL: 'postgres://u:p@db.example.com/postgres', DATABASE_CA_FILE: f }),
    );
    expect(withCa.databaseCaPem).toContain('BEGIN CERTIFICATE'); // verified TLS configured => URL sslmode not required
    expect(() => loadConfig(env({ DATABASE_CA_FILE: join(f, 'missing') }))).toThrow();
  });

  it('DATABASE_CA_PEM supplies the CA inline (including flattened newlines); both forms together or garbage are refused', () => {
    const cert = '-----BEGIN CERTIFICATE-----\nMIIBabc\n-----END CERTIFICATE-----';
    const url = 'postgres://u:p@db.example.com/postgres';
    const inline = loadConfig(env({ ...prod, DATABASE_URL: url, DATABASE_CA_PEM: cert }));
    expect(inline.databaseCaPem).toBe(cert);
    // verified TLS is configured, so the URL does not need sslmode
    expect(inline.env).toBe('production');
    const flattened = loadConfig(
      env({ ...prod, DATABASE_URL: url, DATABASE_CA_PEM: cert.replace(/\n/g, '\\n') }),
    );
    expect(flattened.databaseCaPem).toBe(cert);
    expect(() =>
      loadConfig(
        env({ ...prod, DATABASE_URL: url, DATABASE_CA_PEM: cert, DATABASE_CA_FILE: '/x' }),
      ),
    ).toThrow(/only one/);
    expect(() =>
      loadConfig(env({ ...prod, DATABASE_URL: url, DATABASE_CA_PEM: 'not a certificate' })),
    ).toThrow(/PEM certificate/);
    expect(readCaPem(env({}), () => 'x')).toBeUndefined();
  });

  it('DB_ALLOW_SUPERUSER is opt-in', () => {
    expect(loadConfig(env({})).allowDbSuperuser).toBe(false);
    expect(loadConfig(env({ DB_ALLOW_SUPERUSER: 'true' })).allowDbSuperuser).toBe(true);
    expect(loadConfig(env({ DB_ALLOW_SUPERUSER: '1' })).allowDbSuperuser).toBe(false);
  });
});

describe('explainDbError / describeConnectionTarget', () => {
  const target = describeConnectionTarget(
    'postgresql://trust_app.abc:s3cr3t%40x@db.abc.supabase.co:5432/postgres?sslmode=require',
  );

  it('reports host, port, user and database but never the password', () => {
    expect(target).toEqual({
      host: 'db.abc.supabase.co',
      port: '5432',
      user: 'trust_app.abc',
      database: 'postgres',
    });
    expect(JSON.stringify(target)).not.toContain('s3cr3t');
    expect(describeConnectionTarget('not a url')).toBeUndefined();
  });

  it.each([
    ['IPv6-only host', { code: 'ENETUNREACH', address: '2a05:d018::1' }, /IPv6.*Session pooler/],
    ['unreachable IPv4', { code: 'ENETUNREACH', address: '10.0.0.1' }, /cannot connect to db\.abc/],
    ['timeout', { code: 'ETIMEDOUT' }, /ETIMEDOUT/],
    ['refused', { code: 'ECONNREFUSED' }, /ECONNREFUSED/],
    ['unknown host', { code: 'ENOTFOUND' }, /host name was not found/],
    [
      'wrong password',
      { code: '28P01', message: 'password authentication failed for user "x"' },
      /password in DATABASE_URL does not match/,
    ],
    ['pooler user', { message: 'Tenant or user not found' }, /<role>\.<project-ref>/],
    ['no database', { code: '3D000' }, /does not exist/],
    [
      'untrusted certificate',
      {
        code: 'SELF_SIGNED_CERT_IN_CHAIN',
        message: 'self-signed certificate in certificate chain',
      },
      /DATABASE_CA_PEM/,
    ],
  ])('explains: %s', (_n, err, re) => {
    const msg = explainDbError(err, target);
    expect(msg).toMatch(re);
    expect(msg).not.toContain('s3cr3t');
  });

  it('names the setting that held the URL (owner tools use DATABASE_MIGRATE_URL)', () => {
    const err = { code: '28P01', message: 'password authentication failed for user "postgres"' };
    expect(explainDbError(err, target)).toMatch(/password in DATABASE_URL /);
    expect(explainDbError(err, target, 'DATABASE_MIGRATE_URL')).toMatch(
      /password in DATABASE_MIGRATE_URL /,
    );
  });

  it('leaves unrecognised errors alone', () => {
    expect(explainDbError(new Error('something odd'), target)).toBeUndefined();
  });
});

describe('startup with an unreachable database', () => {
  it('fails with an explanation that names the target and never leaks the password', async () => {
    const { createContainer } = await import('../src/container.ts');
    const cfg = loadConfig(
      env({
        PERSISTENCE: 'postgres',
        DATABASE_URL: 'postgres://trust_app:topsecretpw@127.0.0.1:1/postgres',
      }),
    );
    const e = (await createContainer(cfg).catch((x: Error) => x)) as Error;
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toMatch(/cannot connect to 127\.0\.0\.1:1 as "trust_app" \(ECONNREFUSED\)/);
    expect(e.message).not.toContain('topsecretpw');
  });
});

describe('TLS downgrade regression', () => {
  it.each([
    'sslmode=require&uselibpqcompat=true',
    'ssl=true&sslmode=no-verify',
    'ssl=true&sslmode=disable',
  ])('rejects %s', (query) => {
    expect(tlsProblem(`postgres://u:p@remote.invalid/db?${query}`)).toBeDefined();
  });
});

describe('effective database host', () => {
  it('checks a remote query host even when the URL host is localhost', () => {
    expect(tlsProblem('postgres://u:p@localhost/db?host=remote.invalid')).toBeDefined();
  });
});
