import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
async function setup() {
  env = await makeEnv({ config: { operationsInventoryEnabled: true } });
  const owner = await env.register('owner@example.test');
  const other = await env.register('other@example.test');
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const call = (method: string, path = '', body?: unknown, token = owner.token) =>
    env.call(method, base + path, { token, ...(body ? { body } : {}) });
  const create = async (code = 'rokela-pdf') => {
    const r = await call('POST', '', {
      code,
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    });
    expect(r.status).toBe(201);
    return r.body;
  };
  return { owner, other, base, call, create };
}
describe('OPS-002 inventory HTTP boundary', () => {
  it('keeps rollout disabled by default and validates the setting', async () => {
    expect(loadConfig({ NODE_ENV: 'test' }).operationsInventoryEnabled).toBe(false);
    expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_INVENTORY_ENABLED: 'yes' })).toThrow(
      /true or false/,
    );
    env = await makeEnv();
    const owner = await env.register('owner@example.test');
    const path = `/v1/organizations/${owner.orgId}/operations/applications`;
    expect((await env.call('GET', path, { token: owner.token })).status).toBe(404);
    env.c.config.operationsInventoryEnabled = true;
    expect((await env.call('GET', path, { token: owner.token })).status).toBe(200);
  });
  it('creates inventory, optional active Product mapping, bounded lists and atomic audit', async () => {
    const { owner, call, create } = await setup();
    const app = await create();
    const product = await env.provision(owner.orgId);
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 1,
          product_id: product.productId,
          reason: 'config_change',
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 2,
          product_id: 'prd_' + 'f'.repeat(24),
          reason: 'config_change',
        })
      ).status,
    ).toBe(404);
    const environment = await call('POST', `/${app.id}/environments`, {
      code: 'production',
      kind: 'production',
      reason: 'initial_setup',
    });
    expect(environment.status).toBe(201);
    const path = `/${app.id}/environments/${environment.body.id}/components`;
    const component = await call('POST', path, {
      code: 'web-api',
      kind: 'service',
      dependency_ids: [],
      reason: 'initial_setup',
    });
    expect(component.status).toBe(201);
    expect((await call('GET', path)).body.items).toEqual([component.body]);
    const events = await env.c.audit.list({ orgId: owner.orgId });
    expect(events.filter((e) => e.action.startsWith('operations.'))).toHaveLength(4);
    expect((await env.c.audit.verifyChain()).ok).toBe(true);
  });
  it('refuses unauthenticated, nonmember, ordinary member and operator access; admin can read', async () => {
    const { owner, other, base, call, create } = await setup();
    const app = await create();
    expect((await env.call('GET', base)).status).toBe(401);
    expect((await call('GET', `/${app.id}`, undefined, other.token)).status).toBe(404);
    expect((await call('GET', '', undefined, await env.operatorToken())).status).toBe(404);
    const team = await env.call('POST', '/v1/organizations', {
      token: owner.token,
      body: { name: 'Operations team' },
    });
    const teamBase = `/v1/organizations/${team.body.id}`;
    expect(
      (
        await env.call('POST', teamBase + '/members', {
          token: owner.token,
          body: { email: 'other@example.test', role: 'member' },
        })
      ).status,
    ).toBe(201);
    expect(
      (await env.call('GET', teamBase + '/operations/applications', { token: other.token })).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', teamBase + '/operations/applications', {
          token: other.token,
          body: {
            code: 'no-access',
            owner_user_id: owner.userId,
            criticality: 'high',
            product_id: null,
            reason: 'initial_setup',
          },
        })
      ).status,
    ).toBe(403);
    const admin = await env.register('admin@example.test');
    await env.call('POST', teamBase + '/members', {
      token: owner.token,
      body: { email: 'admin@example.test', role: 'admin' },
    });
    expect(
      (await env.call('GET', teamBase + '/operations/applications', { token: admin.token })).status,
    ).toBe(200);
  });
  it('checks owner membership, strict schemas, immutable identity and safe errors without reflecting submitted data', async () => {
    const { owner, other, call, create } = await setup();
    const body = {
      code: 'safe-code',
      owner_user_id: other.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    };
    expect((await call('POST', '', body)).status).toBe(404);
    for (const extra of [
      { code: 'https://secret.example.test/file' },
      { reason: 'private-reason' },
      { recipient: 'private@example.test' },
      { owner_user_id: 'usr_bad' },
    ]) {
      const r = await call('POST', '', { ...body, owner_user_id: owner.userId, ...extra });
      expect(r.status).toBe(400);
      expect(JSON.stringify(r.body)).not.toMatch(/private|secret|usr_bad|recipient/);
    }
    const app = await create();
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 1,
          reason: 'config_change',
          code: 'rename',
        })
      ).status,
    ).toBe(400);
    expect(
      (await call('PATCH', `/${app.id}`, { expected_version: 1, reason: 'config_change' })).status,
    ).toBe(400);
    expect((await call('GET', `/${app.id}`)).body.version).toBe(1);
  });
  it('preserves tombstones, serializes conflicting updates and blocks disabled/archived parents', async () => {
    const { call, create } = await setup();
    const app = await create();
    const envrow = (
      await call('POST', `/${app.id}/environments`, {
        code: 'staging',
        kind: 'staging',
        reason: 'initial_setup',
      })
    ).body;
    const attempts = await Promise.all(
      [1, 2].map(() =>
        call('PATCH', `/${app.id}`, {
          expected_version: 1,
          state: 'disabled',
          reason: 'maintenance',
        }),
      ),
    );
    expect(attempts.map((r) => r.status).sort()).toEqual([200, 409]);
    expect(
      (
        await call('POST', `/${app.id}/environments`, {
          code: 'blocked-env',
          kind: 'staging',
          reason: 'initial_setup',
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await call('PATCH', `/${app.id}/environments/${envrow.id}`, {
          expected_version: 1,
          state: 'disabled',
          reason: 'maintenance',
        })
      ).status,
    ).toBe(409);
    expect((await call('GET', `/${app.id}/environments/${envrow.id}`)).status).toBe(200);
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 2,
          state: 'active',
          reason: 'restore',
        })
      ).status,
    ).toBe(200);
    expect(
      (await call('DELETE', `/${app.id}`, { expected_version: 3, reason: 'retirement' })).status,
    ).toBe(200);
    expect((await call('GET')).body.items).toEqual([]);
    expect((await call('GET', `/${app.id}`)).body.state).toBe('archived');
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 4,
          state: 'active',
          reason: 'restore',
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await call('POST', '', {
          code: 'rokela-pdf',
          owner_user_id: (await call('GET', `/${app.id}`)).body.owner_user_id,
          criticality: 'high',
          product_id: null,
          reason: 'initial_setup',
        })
      ).status,
    ).toBe(409);
  });
  it('enforces ancestor paths, same-org dependencies and acyclic graphs', async () => {
    const { other, base, call, create } = await setup();
    const a = await create('app-one'),
      b = await create('app-two');
    const e = (
      await call('POST', `/${a.id}/environments`, {
        code: 'production',
        kind: 'production',
        reason: 'initial_setup',
      })
    ).body;
    expect((await call('GET', `/${b.id}/environments/${e.id}`)).status).toBe(404);
    const path = `/${a.id}/environments/${e.id}/components`;
    const x = (
      await call('POST', path, {
        code: 'web-api',
        kind: 'service',
        dependency_ids: [],
        reason: 'initial_setup',
      })
    ).body;
    const y = (
      await call('POST', path, {
        code: 'worker',
        kind: 'worker',
        dependency_ids: [x.id],
        reason: 'initial_setup',
      })
    ).body;
    expect(
      (
        await call('PATCH', path + '/' + x.id, {
          expected_version: 1,
          dependency_ids: [y.id],
          reason: 'config_change',
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await call('PATCH', path + '/' + x.id, {
          expected_version: 1,
          dependency_ids: [x.id],
          reason: 'config_change',
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await call('POST', path, {
          code: 'missing-ref',
          kind: 'service',
          dependency_ids: ['opm_' + 'f'.repeat(24)],
          reason: 'initial_setup',
        })
      ).status,
    ).toBe(404);
    const foreign = base.replace(/org_[a-f0-9]{24}/, other.orgId);
    expect((await env.call('GET', foreign + '/' + a.id, { token: other.token })).status).toBe(404);
    expect((await call('GET', path + '/' + x.id)).body.dependency_ids).toEqual([]);
  });
  it('scopes cursor pagination and rejects malformed/foreign cursors', async () => {
    const { other, base, call, create } = await setup();
    await create('app-one');
    await create('app-two');
    const first = await call('GET', '?limit=1');
    expect(first.body.items).toHaveLength(1);
    expect(first.body.next_cursor).toBeTypeOf('string');
    const second = await call('GET', '?limit=1&cursor=' + first.body.next_cursor);
    expect(second.body.items).toHaveLength(1);
    expect(second.body.items[0].id).not.toBe(first.body.items[0].id);
    expect(second.body.next_cursor).toBeNull();
    for (const query of ['?limit=101', '?cursor=bad', '?unknown=private'])
      expect((await call('GET', query)).status).toBe(400);
    const foreign = base.replace(/org_[a-f0-9]{24}/, other.orgId);
    expect(
      (await env.call('GET', foreign + '?cursor=' + first.body.next_cursor, { token: other.token }))
        .status,
    ).toBe(400);
  });
  it('serializes cap checks beyond pool capacity and counts archived rows', async () => {
    const { owner, call } = await setup();
    const apps = await Promise.all(
      Array.from({ length: 101 }, (_, i) =>
        call('POST', '', {
          code: `app-${i}`,
          owner_user_id: owner.userId,
          criticality: 'high',
          product_id: null,
          reason: 'initial_setup',
        }),
      ),
    );
    expect(apps.filter((r) => r.status === 201)).toHaveLength(100);
    expect(apps.filter((r) => r.status === 409)).toHaveLength(1);
    const app = apps.find((r) => r.status === 201)!.body;
    const envPath = `/${app.id}/environments`;
    const environments = await Promise.all(
      Array.from({ length: 21 }, (_, i) =>
        call('POST', envPath, { code: `env-${i}`, kind: 'staging', reason: 'initial_setup' }),
      ),
    );
    expect(environments.filter((r) => r.status === 201)).toHaveLength(20);
    expect(environments.filter((r) => r.status === 409)).toHaveLength(1);
    const componentPath =
      envPath + '/' + environments.find((r) => r.status === 201)!.body.id + '/components';
    const components = await Promise.all(
      Array.from({ length: 101 }, (_, i) =>
        call('POST', componentPath, {
          code: `component-${i}`,
          kind: 'service',
          dependency_ids: [],
          reason: 'initial_setup',
        }),
      ),
    );
    expect(components.filter((r) => r.status === 201)).toHaveLength(100);
    expect(components.filter((r) => r.status === 409)).toHaveLength(1);
    await call('DELETE', `/${app.id}`, { expected_version: 1, reason: 'retirement' });
    expect(
      (
        await call('POST', '', {
          code: 'replacement',
          owner_user_id: owner.userId,
          criticality: 'high',
          product_id: null,
          reason: 'initial_setup',
        })
      ).status,
    ).toBe(409);
  });
  it('keeps rejected values and internal failures out of errors and automatic request logs', async () => {
    const logs: string[] = [];
    env = await makeEnv({
      config: { operationsInventoryEnabled: true },
      app: { logger: true, logStream: { write: (line) => logs.push(line) } },
    });
    const owner = await env.register('owner@example.test');
    const base = `/v1/organizations/${owner.orgId}/operations/applications`;
    logs.length = 0;
    const marker = 'rejected-private-value-please-hide';
    expect(
      (await env.call('GET', base + '?unexpected=' + marker, { token: owner.token })).status,
    ).toBe(400);
    vi.spyOn(env.c.operations, 'list').mockRejectedValueOnce(new Error(marker));
    const failed = await env.call('GET', base, { token: owner.token });
    expect(failed.status).toBe(503);
    expect(failed.body.code).toBe('unavailable');
    expect(JSON.stringify(failed.body)).not.toContain(marker);
    expect(logs.join('')).not.toContain(marker);
  });
  it('freeze refuses writes after authorization but preserves reads', async () => {
    const { owner, other, call, create } = await setup();
    const app = await create();
    await env.c.privileged.freeze('test-operator', owner.orgId, 'test freeze');
    expect(
      (
        await call('PATCH', `/${app.id}`, {
          expected_version: 1,
          state: 'disabled',
          reason: 'maintenance',
        })
      ).status,
    ).toBe(403);
    expect((await call('GET', `/${app.id}`)).status).toBe(200);
    expect((await call('GET', `/${app.id}`, undefined, other.token)).status).toBe(404);
  });
});
