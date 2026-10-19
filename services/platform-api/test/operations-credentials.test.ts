import { afterEach, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { totpCode } from '../../../packages/auth/src/mfa.ts';
import { makeEnv, PW, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
const MFA_KEY = randomBytes(32).toString('hex');
function decode(value: string) {
  let bits = 0,
    n = 0;
  const out: number[] = [];
  for (const c of value) {
    n = (n << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((n >>> bits) & 255);
    }
  }
  return Buffer.from(out);
}
async function setup(logs?: string[]) {
  env = await makeEnv({
    config: {
      operationsInventoryEnabled: true,
      operationsCredentialsEnabled: true,
      mfaEncryptionKey: MFA_KEY,
    },
    ...(logs ? { app: { logger: true, logStream: { write: (s: string) => logs.push(s) } } } : {}),
  });
  const owner = await env.register('owner@example.test');
  const other = await env.register('other@example.test');
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const app = await env.call('POST', base, {
    token: owner.token,
    body: {
      code: 'rokela-pdf',
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  expect(app.status).toBe(201);
  const environment = await env.call('POST', base + '/' + app.body.id + '/environments', {
    token: owner.token,
    body: { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  });
  expect(environment.status).toBe(201);
  const path = base + '/' + app.body.id + '/environments/' + environment.body.id + '/credentials';
  const scope = {
    orgId: owner.orgId,
    applicationId: app.body.id as string,
    environmentId: environment.body.id as string,
  };
  const begin = await env.call('POST', '/v1/auth/mfa/begin', {
    token: owner.token,
    body: { password: PW },
  });
  expect(begin.status).toBe(200);
  const secret = decode(begin.body.setup_key);
  const current = () => totpCode(secret, Math.floor(+env.clock.now() / 30000));
  const confirmed = await env.call('POST', '/v1/auth/mfa/confirm', {
    token: owner.token,
    body: { password: PW, code: current() },
  });
  expect(confirmed.status).toBe(200);
  env.clock.advance(30000);
  const login = await env.call('POST', '/v1/auth/login', {
    body: { email: 'owner@example.test', password: PW, code: current() },
  });
  expect(login.status).toBe(200);
  owner.token = login.body.token;
  const code = () => {
    env.clock.advance(30000);
    return current();
  };
  const call = (method: string, suffix = '', body?: unknown, token = owner.token) =>
    env.call(method, path + suffix, { token, ...(body ? { body } : {}) });
  const issue = (mfa = code()) =>
    call('POST', '', {
      purpose: 'events:write',
      ttl_seconds: 86400,
      reason: 'initial_setup',
      mfa_code: mfa,
    });
  return {
    owner,
    other,
    base,
    path,
    scope,
    code,
    call,
    issue,
    recovery: confirmed.body.recovery_codes as string[],
  };
}
it('validates credential rollout dependencies, defaults off and gates endpoints/verification end to end', async () => {
  const base = { NODE_ENV: 'test' };
  expect(loadConfig(base).operationsCredentialsEnabled).toBe(false);
  expect(() => loadConfig({ ...base, OPERATIONS_CREDENTIALS_ENABLED: 'yes' })).toThrow(
    /true or false/,
  );
  expect(() => loadConfig({ ...base, OPERATIONS_CREDENTIALS_ENABLED: 'true' })).toThrow(
    /requires inventory/,
  );
  expect(() =>
    loadConfig({
      ...base,
      OPERATIONS_INVENTORY_ENABLED: 'true',
      OPERATIONS_CREDENTIALS_ENABLED: 'true',
    }),
  ).toThrow(/MFA_ENCRYPTION_KEY/);
  expect(
    loadConfig({
      ...base,
      OPERATIONS_INVENTORY_ENABLED: 'true',
      OPERATIONS_CREDENTIALS_ENABLED: 'true',
      MFA_ENCRYPTION_KEY: MFA_KEY,
    }).operationsCredentialsEnabled,
  ).toBe(true);
  const f = await setup();
  env.c.config.operationsCredentialsEnabled = false;
  expect((await f.call('GET')).status).toBe(404);
  env.c.config.operationsCredentialsEnabled = true;
  const one = await f.issue();
  expect(one.status).toBe(201);
  env.c.config.operationsCredentialsEnabled = false;
  await expect(
    env.c.operationsCredentials.withCredential(one.body.token, {}, async () => true),
  ).rejects.toMatchObject({ code: 'unauthenticated' });
});
it('requires actual fresh MFA, consumes it on failure and exposes only no-store metadata thereafter', async () => {
  const logs: string[] = [];
  const f = await setup(logs);
  logs.length = 0;
  const code = f.code();
  const one = await f.issue(code);
  expect(one.status).toBe(201);
  expect(one.headers['cache-control']).toBe('no-store');
  expect(one.body.token).toMatch(/^ops_v1\.opc_[a-f0-9]{32}\.[a-f0-9]{64}$/);
  expect((await f.issue(code)).status).toBe(401);
  const second = await f.issue();
  expect(second.status).toBe(201);
  const failedCode = f.code();
  expect((await f.issue(failedCode)).status).toBe(409);
  expect(
    (
      await f.call('POST', '/' + second.body.credential.id + '/revoke', {
        reason: 'security_response',
        mfa_code: failedCode,
      })
    ).status,
  ).toBe(401);
  expect((await f.issue(f.recovery[0])).status).toBe(400);
  const replaced = await f.call('POST', '/' + one.body.credential.id + '/rotate', {
    ttl_seconds: 86400,
    overlap_seconds: 0,
    mfa_code: f.code(),
    reason: 'routine_rotation',
  });
  expect(replaced.status).toBe(201);
  await expect(
    env.c.operationsCredentials.withCredential(one.body.token, {}, async () => true),
  ).rejects.toMatchObject({ code: 'unauthenticated' });
  await env.c.operationsCredentials.withCredential(second.body.token, {}, async () => true);
  await env.c.operationsCredentials.withCredential(replaced.body.token, {}, async () => true);
  const list = await f.call('GET');
  expect(list.status).toBe(200);
  expect(list.headers['cache-control']).toBe('no-store');
  const page = await f.call('GET', '?limit=1');
  expect(page.body.items).toHaveLength(1);
  const next = await f.call('GET', '?limit=1&cursor=' + page.body.next_cursor);
  expect(next.body.items).toHaveLength(1);
  const serialized =
    JSON.stringify([list.body, ...(await env.c.audit.list({ orgId: f.owner.orgId }))]) +
    logs.join('');
  for (const secret of [
    one.body.token,
    second.body.token,
    one.body.token.split('.')[2],
    code,
    failedCode,
  ])
    expect(serialized).not.toContain(secret);
  expect(serialized).not.toMatch(/secret_hash|secretHash|rotated_at/);
});
it('refuses untrusted fields, wrong purpose, tenant/ancestor spoofing and bearer privilege escalation', async () => {
  const f = await setup();
  expect((await env.call('GET', f.path)).status).toBe(401);
  expect((await f.call('GET', '', undefined, f.other.token)).status).toBe(404);
  const operator = await env.operatorToken();
  expect((await f.call('GET', '', undefined, operator)).status).toBe(404);
  const one = await f.issue();
  expect(one.status).toBe(201);
  expect((await f.call('GET', '', undefined, one.body.token)).status).toBe(401);
  const bad = [
    { source: 'independent_probe' },
    { org_id: f.other.orgId },
    { mfa_authenticated: true },
    { purpose: 'ops:manage_inventory' },
    { ttl_seconds: 7776001 },
    { mfa_code: 'a'.repeat(32) },
  ];
  for (const extra of bad) {
    const r = await f.call('POST', '', {
      purpose: 'events:write',
      ttl_seconds: 86400,
      reason: 'initial_setup',
      mfa_code: f.code(),
      ...extra,
    });
    expect(r.status).toBe(400);
    expect(JSON.stringify(r.body)).not.toMatch(/independent_probe|mfa_authenticated/);
  }
  const foreign = f.path.replace(f.scope.applicationId, 'opa_' + 'f'.repeat(24));
  expect((await env.call('GET', foreign, { token: f.owner.token })).status).toBe(404);
  expect(
    (
      await f.call('POST', '/opc_' + 'f'.repeat(32) + '/revoke', {
        reason: 'security_response',
        mfa_code: f.code(),
      })
    ).status,
  ).toBe(404);
  const team = await env.call('POST', '/v1/organizations', {
    token: f.owner.token,
    body: { name: 'Test team' },
  });
  await env.call('POST', `/v1/organizations/${team.body.id}/members`, {
    token: f.owner.token,
    body: { email: 'other@example.test', role: 'member' },
  });
  expect(
    (await env.call('GET', f.path.replace(f.owner.orgId, team.body.id), { token: f.other.token }))
      .status,
  ).toBe(403);
});
it('rotates with overlap, requires fresh factors for revocation, and permits emergency revoke through freeze', async () => {
  const f = await setup();
  const one = await f.issue();
  expect(one.status).toBe(201);
  const rotated = await f.call('POST', '/' + one.body.credential.id + '/rotate', {
    ttl_seconds: 86400,
    overlap_seconds: 60,
    mfa_code: f.code(),
    reason: 'routine_rotation',
  });
  expect(rotated.status).toBe(201);
  expect(rotated.headers['cache-control']).toBe('no-store');
  await env.c.operationsCredentials.withCredential(one.body.token, f.scope, async () => true);
  await env.c.operationsCredentials.withCredential(rotated.body.token, f.scope, async () => true);
  expect(
    (
      await f.call('POST', '/' + rotated.body.credential.id + '/rotate', {
        ttl_seconds: 86400,
        overlap_seconds: 0,
        mfa_code: f.code(),
        reason: 'routine_rotation',
      })
    ).status,
  ).toBe(409);
  await env.c.privileged.freeze('test-operator', f.owner.orgId, 'test freeze');
  expect((await f.issue()).status).toBe(403);
  await env.c.operationsCredentials.withCredential(rotated.body.token, f.scope, async () => true);
  const revoked = await f.call('POST', '/' + rotated.body.credential.id + '/revoke', {
    mfa_code: f.code(),
    reason: 'security_response',
  });
  expect(revoked.status).toBe(200);
  await expect(
    env.c.operationsCredentials.withCredential(rotated.body.token, {}, async () => true),
  ).rejects.toMatchObject({ code: 'unauthenticated' });
  const again = await f.call('POST', '/' + rotated.body.credential.id + '/revoke', {
    mfa_code: f.code(),
    reason: 'security_response',
  });
  expect(again.status).toBe(200);
  const events = await env.c.audit.list({ orgId: f.owner.orgId });
  expect(events.filter((e) => e.action === 'operations.credential.revoked')).toHaveLength(1);
  expect((await env.c.audit.verifyChain()).ok).toBe(true);
});
it('blocks missing MFA setup and logout even for organization owners', async () => {
  const f = await setup();
  const foreignPath = f.path.replace(f.owner.orgId, f.other.orgId);
  // No tenant lookup or credential read is available to the other organization owner.
  expect((await env.call('GET', foreignPath, { token: f.other.token })).status).toBe(404);
  const otherBase = `/v1/organizations/${f.other.orgId}/operations/applications`;
  const otherApp = await env.call('POST', otherBase, {
    token: f.other.token,
    body: {
      code: 'other-app',
      owner_user_id: f.other.userId,
      criticality: 'low',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  const otherEnv = await env.call('POST', otherBase + '/' + otherApp.body.id + '/environments', {
    token: f.other.token,
    body: { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  });
  expect(
    (
      await env.call(
        'POST',
        otherBase + '/' + otherApp.body.id + '/environments/' + otherEnv.body.id + '/credentials',
        {
          token: f.other.token,
          body: {
            purpose: 'events:write',
            ttl_seconds: 86400,
            reason: 'initial_setup',
            mfa_code: '123456',
          },
        },
      )
    ).status,
  ).toBe(403);
  const loggedOut = await env.call('POST', '/v1/auth/logout', { token: f.owner.token });
  expect(loggedOut.status).toBe(204);
  expect((await f.issue()).status).toBe(401);
});
