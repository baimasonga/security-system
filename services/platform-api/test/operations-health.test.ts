import { afterEach, expect, it, vi } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
import { persistenceReadiness } from '../src/readiness.ts';
let env: Env;
afterEach(async () => env?.app.close());
it('serves scoped health/history behind its own flag and current organization authorization', async () => {
  expect(loadConfig({ NODE_ENV: 'test' }).operationsHealthEnabled).toBe(false);
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_HEALTH_ENABLED: 'true' })).toThrow(
    /requires/,
  );
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_HEALTH_ENABLED: 'yes' })).toThrow(
    /true or false/,
  );
  env = await makeEnv({
    config: { operationsInventoryEnabled: true, operationsHealthEnabled: true },
  });
  const owner = await env.register('owner@example.test'),
    other = await env.register('other@example.test');
  const principal = await env.c.auth.authenticate(owner.token);
  const a = await env.c.operations.createApplication(principal, owner.orgId, {
    code: 'health-app',
    ownerUserId: owner.userId,
    criticality: 'high',
    productId: null,
    reason: 'initial_setup',
  });
  const scope = { orgId: owner.orgId, applicationId: a.id };
  const e = await env.c.operations.createEnvironment(principal, scope, {
    code: 'staging',
    kind: 'staging',
    reason: 'initial_setup',
  });
  const c = await env.c.operations.createComponent(
    principal,
    { ...scope, environmentId: e.id },
    { code: 'api', kind: 'service', dependencyIds: [], reason: 'initial_setup' },
  );
  const path = `/v1/organizations/${owner.orgId}/operations/applications/${a.id}/environments/${e.id}`;
  const health = await env.call('GET', path + '/health', { token: owner.token });
  expect(health.status).toBe(200);
  expect(health.body.independent_probe).toBe(false);
  expect(health.body.components[0].status).toBe('unknown');
  expect(health.headers['cache-control']).toBe('no-store');
  expect((await env.call('GET', path + '/health', { token: other.token })).status).toBe(404);
  expect((await env.call('GET', path + '/health', { token: 'ops_v1.invalid' })).status).toBe(401);
  const team = await env.c.auth.createOrganization(principal, 'Health access team');
  await env.c.auth.addMember(principal, team.id, 'other@example.test', 'member');
  const scopedA = await env.c.operations.createApplication(principal, team.id, {
    code: 'private-app',
    ownerUserId: owner.userId,
    criticality: 'low',
    productId: null,
    reason: 'initial_setup',
  });
  const scopedE = await env.c.operations.createEnvironment(
    principal,
    { orgId: team.id, applicationId: scopedA.id },
    { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  );
  expect(
    (
      await env.call(
        'GET',
        `/v1/organizations/${team.id}/operations/applications/${scopedA.id}/environments/${scopedE.id}/health`,
        { token: other.token },
      )
    ).status,
  ).toBe(403);
  expect(
    (
      await env.call('GET', path.replace(owner.orgId, 'org_' + 'f'.repeat(24)) + '/health', {
        token: owner.token,
      })
    ).status,
  ).toBe(404);

  expect(
    (await env.call('GET', path + '/health?private-user@example.test=x', { token: owner.token }))
      .status,
  ).toBe(400);
  const query = `?from=${encodeURIComponent(new Date(+env.clock.now() - 3600000).toISOString())}&to=${encodeURIComponent(env.clock.now().toISOString())}`;
  const history = await env.call('GET', path + `/components/${c.id}/history` + query, {
    token: owner.token,
  });
  expect(history.status).toBe(200);
  expect(history.body.items).toEqual([]);
  expect(history.body.coverage).toBe('observations_only');
  env.c.config.operationsHealthEnabled = false;
  expect((await env.call('GET', path + '/health', { token: owner.token })).status).toBe(404);
});
it('keeps readiness separate from liveness and hides persistence diagnostics', async () => {
  env = await makeEnv();
  expect((await env.call('GET', '/readyz')).status).toBe(200);
  env.c.readiness = async () => false;
  expect((await env.call('GET', '/readyz')).body).toEqual({ status: 'unavailable' });
  expect((await env.call('GET', '/readyz')).status).toBe(503);
  expect((await env.call('GET', '/healthz')).status).toBe(200);
});
it('bounds slow persistence checks and coalesces pending queries', async () => {
  let calls = 0;
  const check = persistenceReadiness(() => {
    calls++;
    return new Promise(() => {});
  }, 5);
  expect(await Promise.all([check(), check(), check()])).toEqual([false, false, false]);
  expect(calls).toBe(1);
  expect(
    await persistenceReadiness(async () => {
      throw new Error('private database password');
    }, 5)(),
  ).toBe(false);
});

it('reuses a timed-out readiness result while persistence remains wedged', async () => {
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'performance'] });
  try {
    let calls = 0;
    const check = persistenceReadiness(() => {
      calls++;
      return new Promise(() => {});
    }, 5);
    const first = check();
    await vi.advanceTimersByTimeAsync(5);
    expect(await first).toBe(false);
    await vi.advanceTimersByTimeAsync(1001);
    let resolved = false;
    const later = check().then((value) => {
      resolved = true;
      return value;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(resolved).toBe(true);
    expect(await later).toBe(false);
    expect(calls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it('expires readiness cache by monotonic time when the wall clock rolls backward', async () => {
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'performance'] });
  try {
    let calls = 0;
    const check = persistenceReadiness(async () => {
      if (++calls > 1) throw new Error('unavailable');
    });
    expect(await check()).toBe(true);
    await vi.advanceTimersByTimeAsync(1001);
    vi.setSystemTime(new Date(Date.now() - 3600000));
    expect(await check()).toBe(false);
    expect(calls).toBe(2);
  } finally {
    vi.useRealTimers();
  }
});
