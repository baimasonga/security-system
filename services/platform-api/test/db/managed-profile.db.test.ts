import { randomBytes } from 'node:crypto';
import { describe, expect, it, afterAll, beforeAll } from 'vitest';
import pg from 'pg';
import { generateEd25519 } from '@trust/crypto';
import { loadConfig } from '../../src/config.ts';
import { createContainer } from '../../src/container.ts';
import { MIGRATIONS_DIR, applyMigrations } from '../../src/db/migrate.ts';
import { TABLE_PRIVILEGES, applyAppGrants } from '../../src/db/grants.ts';
import { evaluate, gatherFacts } from '../../src/db/profile-check.ts';

const url = process.env['DATABASE_URL'];
const suffix = randomBytes(4).toString('hex');
const SCHEMA = `trust_${suffix}`;
const APP = `app_${suffix}`;
const SIMULATED = ['anon', 'authenticated', 'service_role', 'authenticator'];

const as = (role: string, over: Record<string, string> = {}) => {
  const u = new URL(url!);
  u.username = role;
  u.password = '';
  for (const [k, v] of Object.entries(over)) u.searchParams.set(k, v);
  return u.toString();
};

describe.skipIf(!url)('managed-database profile (ADR-012)', () => {
  let owner: pg.Client; // the cluster superuser: stands in for the schema owner here
  const createdRoles: string[] = [];
  const pools: pg.Pool[] = [];

  const appPool = () => {
    const p = new pg.Pool({ connectionString: as(APP), max: 2 }); // NO startup options: the role carries the schema
    pools.push(p);
    return p;
  };
  const facts = async (db: pg.Pool, expectedSchema: string | undefined = SCHEMA) =>
    evaluate(
      await gatherFacts(db, { host: '127.0.0.1', expectedSchema, migrationsDir: MIGRATIONS_DIR }),
    );
  const status = (cs: ReturnType<typeof evaluate>, id: string) =>
    cs.find((c) => c.id === id)?.status;

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    for (const r of SIMULATED) {
      const has =
        (await owner.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [r])).rows.length > 0;
      if (!has) {
        await owner.query(`CREATE ROLE ${r} ${r === 'authenticator' ? 'LOGIN' : 'NOLOGIN'}`);
        createdRoles.push(r);
      }
    }
    await owner.query(`CREATE ROLE ${APP} LOGIN`);
    createdRoles.push(APP);
    // Migrate into a private schema, as on a managed platform.
    await applyMigrations(owner, MIGRATIONS_DIR, { schema: SCHEMA });
    // What Supabase's defaults would do: the API roles can read what the owner creates.
    await owner.query(`GRANT USAGE ON SCHEMA ${SCHEMA} TO anon, authenticated, service_role`);
    await owner.query(
      `GRANT SELECT ON ALL TABLES IN SCHEMA ${SCHEMA} TO anon, authenticated, service_role`,
    );
    // Role-level settings travel through poolers (startup options do not).
    await owner.query(`ALTER ROLE ${APP} SET search_path = ${SCHEMA}`);
  });
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end().catch(() => undefined)));
    await owner?.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`).catch(() => undefined);
    for (const r of createdRoles.reverse()) {
      await owner?.query(`DROP OWNED BY ${r}`).catch(() => undefined);
      await owner?.query(`DROP ROLE IF EXISTS ${r}`).catch(() => undefined);
    }
    await owner?.end().catch(() => undefined);
  });

  it('migrates into the private schema and nowhere else', async () => {
    const inSchema = (
      await owner.query('SELECT tablename FROM pg_tables WHERE schemaname = $1', [SCHEMA])
    ).rows.map((r) => r.tablename as string);
    expect(inSchema).toEqual(
      expect.arrayContaining(['audit_events', 'licenses', 'rate_limits', 'schema_migrations']),
    );
    const strays = (
      await owner.query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1)",
        [inSchema],
      )
    ).rows;
    expect(strays).toEqual([]);
    // the audit triggers/functions live in the schema too
    const fns = (
      await owner.query(
        'SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1',
        [SCHEMA],
      )
    ).rows.map((r) => r.proname as string);
    expect(fns).toContain('audit_events_immutable');
    await expect(applyMigrations(owner, MIGRATIONS_DIR, { schema: 'Bad;Name' })).rejects.toThrow(
      /invalid schema name/,
    );
  });

  it('every table has a deliberate grant policy (a new table cannot be forgotten), and no stale entries', async () => {
    const tables = (
      await owner.query('SELECT tablename FROM pg_tables WHERE schemaname = $1', [SCHEMA])
    ).rows
      .map((r) => r.tablename as string)
      .sort();
    expect(Object.keys(TABLE_PRIVILEGES).sort()).toEqual(tables);
    // and the audit tables never get rewrite rights in the policy itself
    for (const t of ['audit_events', 'audit_anchors'])
      expect(TABLE_PRIVILEGES[t]).toEqual(['SELECT', 'INSERT']);
    expect(TABLE_PRIVILEGES['audit_chains']).not.toContain('DELETE');
    for (const privs of Object.values(TABLE_PRIVILEGES)) expect(privs).not.toContain('TRUNCATE');
  });

  it('refuses unsafe grant targets', async () => {
    await expect(applyAppGrants(owner, { schema: SCHEMA, role: 'postgres' })).rejects.toThrow(
      /superuser|differ/,
    );
    await expect(
      applyAppGrants(owner, { schema: SCHEMA, role: 'no_such_role_xyz' }),
    ).rejects.toThrow(/does not exist/);
    await expect(applyAppGrants(owner, { schema: SCHEMA, role: 'bad;role' })).rejects.toThrow(
      /invalid schema name/,
    );
  });

  it('db:check fails before the grants (API roles can read, no table access for the app) and passes after', async () => {
    const before = await facts(appPool());
    expect(status(before, 'api-roles-locked-out')).toBe('fail');
    expect(status(before, 'table-coverage')).toBe('fail');

    const applied = await applyAppGrants(owner, { schema: SCHEMA, role: APP });
    expect(
      applied.some((s) => s.includes('audit_events') && /UPDATE|DELETE|TRUNCATE/.test(s)),
    ).toBe(false);

    const after = await facts(appPool());
    expect(after.filter((c) => c.status === 'fail')).toEqual([]);
    expect(status(after, 'tls')).toBe('warn'); // loopback test server: not encrypted, but local
    expect(status(after, 'not-superuser')).toBe('pass');
    expect(status(after, 'api-roles-locked-out')).toBe('pass');
    // running it again changes nothing (idempotent)
    await applyAppGrants(owner, { schema: SCHEMA, role: APP });
    expect((await facts(appPool())).filter((c) => c.status === 'fail')).toEqual([]);
  });

  it('db:check flags the owner/superuser connection, a wrong schema, and an API gateway that exposes the schema', async () => {
    const ownerPool = new pg.Pool({ connectionString: url, max: 1, ...{} });
    pools.push(ownerPool);
    await ownerPool.query(`SET search_path = ${SCHEMA}`).catch(() => undefined);
    const c = await pool1Query(ownerPool);
    expect(status(c, 'not-superuser')).toBe('fail');
    expect(status(c, 'not-owner')).toBe('fail');
    expect(status(c, 'audit-append-only')).toBe('fail');
    expect(status(c, 'no-ddl')).toBe('fail');

    const wrong = await facts(appPool(), 'some_other_schema');
    expect(status(wrong, 'schema')).toBe('fail');

    await owner.query(`ALTER ROLE authenticator SET pgrst.db_schemas = 'public,${SCHEMA}'`);
    expect(status(await facts(appPool()), 'api-not-exposed')).toBe('fail');
    await owner.query(`ALTER ROLE authenticator SET pgrst.db_schemas = 'public'`);
    expect(status(await facts(appPool()), 'api-not-exposed')).toBe('pass');
  });

  async function pool1Query(p: pg.Pool) {
    // one dedicated connection so SET search_path sticks
    const client = await p.connect();
    try {
      await client.query(`SET search_path = ${SCHEMA}`);
      return evaluate(
        await gatherFacts(client, {
          host: '127.0.0.1',
          expectedSchema: SCHEMA,
          migrationsDir: MIGRATIONS_DIR,
        }),
      );
    } finally {
      client.release();
    }
  }

  it('the application role can do its job but cannot rewrite evidence, change the schema or disable triggers', async () => {
    await applyAppGrants(owner, { schema: SCHEMA, role: APP });
    const p = appPool();
    expect((await p.query('SELECT current_user AS u, current_schema() AS s')).rows[0]).toEqual({
      u: APP,
      s: SCHEMA,
    });
    const denied = async (sql: string) =>
      expect(p.query(sql), sql).rejects.toMatchObject({ code: '42501' }); // insufficient_privilege

    // (heads advance through the normal append path, covered by the behavioural suites running as this role)
    await denied('DELETE FROM audit_chains');
    await denied('UPDATE audit_events SET action = action');
    await denied('DELETE FROM audit_events');
    await denied('TRUNCATE audit_events');
    await denied('UPDATE audit_anchors SET status = status');
    await denied('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update');
    await denied('DROP TABLE audit_events');
    await denied('CREATE TABLE evil (x int)');
    await denied('CREATE FUNCTION evil() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$');
    await denied("INSERT INTO schema_migrations (version, checksum) VALUES ('9999_x', 'x')");
    await denied(
      'CREATE TRIGGER t BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()',
    );
    // and the API roles cannot read anything
    const sess = new pg.Client({ connectionString: url });
    await sess.connect();
    try {
      for (const r of ['anon', 'authenticated', 'service_role']) {
        await sess.query(`SET ROLE ${r}`);
        await expect(sess.query(`SELECT 1 FROM ${SCHEMA}.users`), r).rejects.toMatchObject({
          code: '42501',
        });
        await sess.query('RESET ROLE');
      }
    } finally {
      await sess.end();
    }
  });

  it('the documented procedure works end to end: setup SQL, then migrate, db:grants and db:check as separate processes', async () => {
    const { spawnSync } = await import('node:child_process');
    const { readFileSync } = await import('node:fs');
    const sql = readFileSync(
      new URL('../../../../docs/deploy/supabase-setup.sql', import.meta.url),
      'utf8',
    );
    // The guide hardcodes `trust` / `trust_app`; use a scratch database so nothing else is disturbed.
    const dbName = `guide_${suffix}`;
    await owner.query(`CREATE DATABASE ${dbName}`);
    const at = (user: string, db = dbName) => {
      const u = new URL(url!);
      u.username = user;
      u.password = '';
      u.pathname = `/${db}`;
      return u.toString();
    };
    const guide = new pg.Client({ connectionString: at('postgres') });
    await guide.connect();
    let role = false;
    try {
      await guide.query(sql); // exactly what an operator pastes into the SQL editor
      role = true;
      const base = {
        ...process.env,
        DB_SCHEMA: 'trust',
        APP_DB_ROLE: 'trust_app',
        DATABASE_MIGRATE_URL: at('postgres'),
      };
      delete (base as Record<string, unknown>)['DATABASE_URL'];
      const run = (script: string, extra: Record<string, string> = {}) =>
        spawnSync('node', [script], { env: { ...base, ...extra }, encoding: 'utf8' });

      const mig = run('tools/migrate.ts');
      expect(mig.status, mig.stderr).toBe(0);
      expect(mig.stdout).toContain('0005_shared_rate_state');
      const before = run('tools/db-check.ts', { DATABASE_URL: at('trust_app') });
      expect(before.status).toBe(1); // nothing granted yet: the app role sees no tables
      const grants = run('tools/db-grants.ts');
      expect(grants.status, grants.stderr).toBe(0);
      const check = run('tools/db-check.ts', { DATABASE_URL: at('trust_app') });
      expect(check.status, check.stdout + check.stderr).toBe(0);
      expect(check.stdout).toMatch(/PASS\s+audit-append-only/);
      expect(check.stdout).toMatch(/^OK/m);
      // the owner's connection must NOT pass the profile
      const owned = run('tools/db-check.ts', { DATABASE_URL: at('postgres') });
      expect(owned.status).toBe(1);
      expect(owned.stdout).toMatch(/FAIL\s+not-superuser/);
      // missing configuration is a usage error, not a pass
      expect(run('tools/db-grants.ts', { APP_DB_ROLE: '' }).status).toBe(2);
    } finally {
      await guide.end().catch(() => undefined);
      await owner.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => undefined);
      if (role) {
        await owner.query('DROP OWNED BY trust_app').catch(() => undefined);
        await owner.query('DROP ROLE IF EXISTS trust_app').catch(() => undefined);
      }
    }
  }, 120_000);

  it('tools/bootstrap-operator.ts promotes an existing user using only the least-privilege role, with a mandatory reason', async () => {
    const { spawnSync } = await import('node:child_process');
    await applyAppGrants(owner, { schema: SCHEMA, role: APP });
    await owner.query(
      `INSERT INTO ${SCHEMA}.users (id, email, password_hash) VALUES ('usr_boot', 'boss@example.test', 'x')`,
    );
    const run = (...args: string[]) =>
      spawnSync('node', ['tools/bootstrap-operator.ts', ...args], {
        env: { ...process.env, DATABASE_URL: as(APP) }, // role-level search_path supplies the schema
        encoding: 'utf8',
      });
    expect(run('--email', 'boss@example.test').status).toBe(2); // no reason
    expect(run('--reason', 'initial operator').status).toBe(2); // no email
    const tooShort = run('--email', 'boss@example.test', '--reason', 'x');
    expect(tooShort.status).toBe(1);
    expect(tooShort.stderr).toMatch(/reason is required/);
    const ghost = run('--email', 'nobody@example.test', '--reason', 'initial operator');
    expect(ghost.status).toBe(1);
    expect(ghost.stderr).toMatch(/user not found/);
    expect(
      (await owner.query(`SELECT platform_role FROM ${SCHEMA}.users WHERE id = 'usr_boot'`))
        .rows[0]!.platform_role,
    ).toBe('none');

    const ok = run('--email', ' Boss@Example.test ', '--reason', 'initial operator');
    expect(ok.status, ok.stderr).toBe(0);
    expect(
      (await owner.query(`SELECT platform_role FROM ${SCHEMA}.users WHERE id = 'usr_boot'`))
        .rows[0]!.platform_role,
    ).toBe('platform_admin');
    const ev = (
      await owner.query(
        `SELECT actor_type, reason, target_id FROM ${SCHEMA}.audit_events WHERE action = 'operator.bootstrapped'`,
      )
    ).rows;
    expect(ev).toEqual([
      { actor_type: 'system', reason: 'initial operator', target_id: 'usr_boot' },
    ]);
  });

  describe('startup guards (production)', () => {
    const pem = generateEd25519().privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const prod = (databaseUrl: string, over: Record<string, string> = {}) => ({
      ...loadConfig({
        NODE_ENV: 'production',
        PERSISTENCE: 'postgres',
        LICENSE_KEY_PEPPER: 'x'.repeat(40),
        PSEUDONYM_KEY: 'x'.repeat(40),
        AUDIT_ANCHOR_DISABLED: 'true',
        DATABASE_URL: databaseUrl,
        LICENSE_SIGNING_KEY_PEM: pem,
        DATABASE_INSECURE_TRANSPORT: 'true', // the throwaway test server has no TLS
        ...over,
      } as NodeJS.ProcessEnv),
      scrypt: { N: 1024, r: 8, p: 1 },
    });

    it('starts with the least-privilege role, using the role-level search_path (no startup options)', async () => {
      await applyAppGrants(owner, { schema: SCHEMA, role: APP });
      const c = await createContainer(prod(as(APP), { DB_SCHEMA: SCHEMA }));
      try {
        expect(c.dbWarnings).toEqual([]);
        const reg = await c.auth.register({
          email: 'prod@example.test',
          password: 'correct horse battery',
        });
        expect(reg.user.id).toMatch(/^usr_/);
        const v = await c.audit.verifyChain();
        expect(v, JSON.stringify(v)).toMatchObject({ ok: true });
      } finally {
        await c.close();
      }
    });

    it('refuses a superuser in production unless explicitly accepted, and then warns', async () => {
      const su = prod(as('postgres'), { DB_SCHEMA: SCHEMA });
      // the superuser connection lands in "public" unless its search_path says otherwise: set it at role level
      await owner.query(`ALTER ROLE postgres SET search_path = ${SCHEMA}`);
      try {
        await expect(createContainer(su)).rejects.toThrow(/superuser/);
        const ok = await createContainer(
          prod(as('postgres'), { DB_SCHEMA: SCHEMA, DB_ALLOW_SUPERUSER: 'true' }),
        );
        try {
          expect(ok.dbWarnings.join(' ')).toMatch(/superuser/);
        } finally {
          await ok.close();
        }
      } finally {
        await owner.query('ALTER ROLE postgres RESET search_path');
      }
    });

    it('refuses to start when the role does not land in the configured schema', async () => {
      await expect(
        createContainer(prod(as(APP), { DB_SCHEMA: 'some_other_schema' })),
      ).rejects.toThrow(/search_path/);
    });
  });
});
