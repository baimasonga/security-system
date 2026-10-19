// OPS-003 integrity/serialization test. Real HTTP + disposable PostgreSQL schema, never production.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { buildApp } from '../../services/platform-api/src/app.ts';
import { createContainer } from '../../services/platform-api/src/container.ts';
import { loadConfig } from '../../services/platform-api/src/config.ts';
import { applyMigrations, MIGRATIONS_DIR } from '../../services/platform-api/src/db/migrate.ts';
import { totpCode } from '../../packages/auth/src/mfa.ts';
const url = process.env['DATABASE_URL'];
if (!url) throw new Error('DATABASE_URL required: disposable local database only');
const schema = 'ops_credentials_load_' + randomBytes(6).toString('hex');
const admin = new pg.Client({ connectionString: url });
await admin.connect();
const pool = new pg.Pool({
  connectionString: url,
  options: `-c search_path=${schema}`,
  application_name: schema,
  max: 2,
});
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
let time = new Date('2026-10-19T00:00:00Z');
const clock = { now: () => time };
const advance = () => {
  time = new Date(+time + 30000);
};
const decode = (value: string) => {
  let n = 0,
    bits = 0;
  const result: number[] = [];
  for (const c of value) {
    n = (n << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      result.push((n >>> bits) & 255);
    }
  }
  return Buffer.from(result);
};
try {
  assert.equal((await admin.query('SHOW fsync')).rows[0]?.fsync, 'on');
  await admin.query(`CREATE SCHEMA ${schema}`);
  const migrator = await pool.connect();
  try {
    await applyMigrations(migrator, MIGRATIONS_DIR);
  } finally {
    migrator.release();
  }
  const c = await createContainer(
    {
      ...loadConfig({ NODE_ENV: 'test' }),
      operationsInventoryEnabled: true,
      operationsCredentialsEnabled: true,
      mfaEncryptionKey: randomBytes(32).toString('hex'),
      scrypt: { N: 1024, r: 8, p: 1 },
      rateLimits: {
        global: 100000,
        register: 100000,
        login: 100000,
        challenge: 100000,
        activate: 100000,
        sharing: 100000,
      },
    },
    { pool, clock },
  );
  app = await buildApp(c);
  const origin = await app.listen({ host: '127.0.0.1', port: 0 });
  const request = async (method: string, path: string, token: string, body?: unknown) => {
    const r = await fetch(origin + path, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: r.status, body: (await r.json()) as any };
  };
  const actors: Array<{ token: string; secret: Buffer; userId: string; email: string }> = [];
  for (let i = 0; i < 3; i++) {
    const email = `load-${i}@example.test`,
      password = 'local-load-password-only';
    const account = await c.auth.register({ email, password });
    let token = (await c.auth.login({ email, password })).token;
    const begin = await request('POST', '/v1/auth/mfa/begin', token, { password });
    assert.equal(begin.status, 200);
    const secret = decode(begin.body.setup_key);
    const code = () => totpCode(secret, Math.floor(+time / 30000));
    assert.equal(
      (await request('POST', '/v1/auth/mfa/confirm', token, { password, code: code() })).status,
      200,
    );
    advance();
    token = (await c.auth.login({ email, password, code: code() })).token;
    actors.push({ token, secret, userId: account.user.id, email });
  }
  const owner = actors[0]!;
  const principal = await c.auth.authenticate(owner.token);
  const org = await c.auth.createOrganization(principal, 'Operations load');
  for (const actor of actors.slice(1))
    await c.auth.addMember(principal, org.id, actor.email, 'admin');
  const application = await c.operations.createApplication(principal, org.id, {
    code: 'load-app',
    ownerUserId: owner.userId,
    criticality: 'high',
    productId: null,
    reason: 'initial_setup',
  });
  const env = await c.operations.createEnvironment(
    principal,
    { orgId: org.id, applicationId: application.id },
    { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  );
  const scope = { orgId: org.id, applicationId: application.id, environmentId: env.id };
  const path = `/v1/organizations/${org.id}/operations/applications/${application.id}/environments/${env.id}/credentials`;
  const mutation = (actor: typeof owner, extra: Record<string, unknown> = {}) => ({
    mfa_code: totpCode(actor.secret, Math.floor(+time / 30000)),
    reason: 'security_response',
    ...extra,
  });
  advance();
  const issuing = await Promise.all(
    actors.map((actor) =>
      request(
        'POST',
        path,
        actor.token,
        mutation(actor, { purpose: 'events:write', ttl_seconds: 86400 }),
      ),
    ),
  );
  assert.equal(issuing.filter((r) => r.status === 201).length, 2);
  assert.equal(issuing.filter((r) => r.status === 409).length, 1);
  const secrets = issuing.filter((r) => r.status === 201).map((r) => r.body.token as string);
  for (const issued of issuing.filter((r) => r.status === 201)) {
    advance();
    assert.equal(
      (
        await request(
          'POST',
          path + '/' + issued.body.credential.id + '/revoke',
          owner.token,
          mutation(owner),
        )
      ).status,
      200,
    );
  }
  advance();
  const initial = await request(
    'POST',
    path,
    owner.token,
    mutation(owner, { purpose: 'events:write', ttl_seconds: 86400 }),
  );
  assert.equal(initial.status, 201);
  secrets.push(initial.body.token);
  advance();
  const rotating = await Promise.all(
    actors.map((actor) =>
      request(
        'POST',
        path + '/' + initial.body.credential.id + '/rotate',
        actor.token,
        mutation(actor, { ttl_seconds: 86400, overlap_seconds: 60 }),
      ),
    ),
  );
  assert.equal(rotating.filter((r) => r.status === 201).length, 1);
  assert.equal(rotating.filter((r) => r.status === 409).length, 2);
  const successor = rotating.find((r) => r.status === 201)!.body;
  secrets.push(successor.token);
  await c.operationsCredentials.withCredential(initial.body.token, scope, async () => true);
  await c.operationsCredentials.withCredential(successor.token, scope, async () => true);
  advance();
  assert.equal(
    (
      await request(
        'POST',
        path + '/' + successor.credential.id + '/rotate',
        owner.token,
        mutation(owner, { ttl_seconds: 86400, overlap_seconds: 0 }),
      )
    ).status,
    409,
  );
  let release!: () => void, entered!: () => void;
  const held = new Promise<void>((r) => {
    release = r;
  });
  const ready = new Promise<void>((r) => {
    entered = r;
  });
  const consuming = c.operationsCredentials.withCredential(successor.token, scope, async () => {
    entered();
    await held;
    return 'committed';
  });
  await ready;
  advance();
  const revoking = request(
    'POST',
    path + '/' + successor.credential.id + '/revoke',
    owner.token,
    mutation(owner),
  );
  try {
    const deadline = Date.now() + 5000;
    let blocked = false;
    while (Date.now() < deadline) {
      const rows = await admin.query(
        "SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%operations_accounts%'",
        [schema],
      );
      if (rows.rows.length) {
        blocked = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(blocked, true, 'revocation must wait for the guarded transaction lock');
  } finally {
    release();
  }
  assert.equal(await consuming, 'committed');
  assert.equal((await revoking).status, 200);
  await assert.rejects(
    c.operationsCredentials.withCredential(successor.token, scope, async () => true),
    { code: 'unauthenticated' },
  );
  const rows = await pool.query('SELECT * FROM operations_credentials');
  assert.equal(rows.rows.length, 4);
  for (const token of secrets)
    assert.equal(JSON.stringify(rows.rows).includes(token.split('.')[2]!), false);
  const audit = (await c.audit.list({ orgId: org.id })).filter((e) =>
    e.action.startsWith('operations.credential.'),
  );
  assert.equal(audit.length, 8);
  assert.equal((await c.audit.verifyChain()).ok, true);
  console.log(
    JSON.stringify({
      scenario: 'operations-credentials-contention',
      actors: 3,
      pool: 2,
      issue: { created: 2, conflict: 1 },
      rotation: { created: 1, conflict: 2 },
      overlap_conflict: 1,
      guarded_commit_before_revoke: true,
      revoked_refused: true,
      persisted_credentials: 4,
      credential_audit_events: 8,
      plaintext_in_db: false,
      fsync: 'on',
      audit_verified: true,
    }),
  );
} finally {
  await app?.close();
  await pool.end();
  await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await admin.end();
}
