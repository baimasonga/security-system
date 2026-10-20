import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { expect, it } from 'vitest';
it('the real predeploy CLI migrates, grants and checks the runtime role; reruns repair missing rights', async () => {
  const ownerUrl = process.env['DATABASE_URL'];
  if (!ownerUrl) throw new Error('disposable DATABASE_URL required');
  const suffix = randomBytes(6).toString('hex'),
    schema = 'pd_' + suffix,
    role = 'pd_app_' + suffix;
  const password = 'predeploy-fixture-only';
  const appUrl = new URL(ownerUrl);
  appUrl.username = role;
  appUrl.password = password;
  const owner = new pg.Client({ connectionString: ownerUrl });
  await owner.connect();
  const root = fileURLToPath(new URL('../../../../', import.meta.url));
  const env = {
    ...process.env,
    DATABASE_URL: appUrl.toString(),
    DATABASE_MIGRATE_URL: ownerUrl,
    DB_SCHEMA: schema,
    APP_DB_ROLE: role,
  };
  const run = (tool: string) =>
    spawnSync(process.execPath, [root + '/tools/' + tool], { env, encoding: 'utf8' });
  try {
    await owner.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
    await owner.query(`CREATE SCHEMA ${schema}`);
    await owner.query(`ALTER ROLE ${role} SET search_path=${schema}`);
    const first = run('predeploy.ts');
    expect(first.status, first.stdout + first.stderr).toBe(0);
    expect(first.stdout).toContain(
      'predeploy completed: migrations, grants and profile verification',
    );
    expect(first.stdout).not.toContain(password);
    await owner.query(`REVOKE UPDATE ON ${schema}.operations_incidents FROM ${role}`);
    const denied = run('db-check.ts');
    expect(denied.status).toBe(1);
    expect(denied.stdout).toContain('required-grants');
    const second = run('predeploy.ts');
    expect(second.status, second.stdout + second.stderr).toBe(0);
    const app = new pg.Client({ connectionString: appUrl.toString() });
    await app.connect();
    try {
      const r = await app.query(
        "SELECT has_table_privilege(current_user,'operations_incidents','UPDATE') AS upd,has_table_privilege(current_user,'operations_incidents','DELETE') AS del",
      );
      expect(r.rows[0]).toEqual({ upd: true, del: false });
    } finally {
      await app.end();
    }
  } finally {
    await owner.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await owner.query(`DROP OWNED BY ${role}`).catch(() => undefined);
    await owner.query(`DROP ROLE IF EXISTS ${role}`);
    await owner.end();
  }
}, 30000);
