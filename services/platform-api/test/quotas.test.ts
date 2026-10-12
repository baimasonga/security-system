import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());
async function setup() {
  env = await makeEnv();
  const user = await env.register('quota@example.test'),
    other = await env.register('other@example.test');
  const grant = await env.provision(user.orgId);
  const operator = await env.operatorToken();
  await env.call('PATCH', `/v1/admin/organizations/${user.orgId}/subscriptions/${grant.subId}`, {
    token: operator,
    body: { current_period_end: '2026-06-01T00:00:00Z', reason: 'Test multiple months' },
  });
  expect(
    (
      await env.call('PATCH', `/v1/admin/plans/${grant.planId}`, {
        token: operator,
        body: { entitlements: { ocr_pages_monthly: 5 }, reason: 'Configure metering' },
      })
    ).status,
  ).toBe(200);
  const path = `/v1/organizations/${user.orgId}/licenses/${grant.licenseId}/usage`;
  const consume = (key: string, units = 3, token = user.token) =>
    env.call('POST', path, {
      token,
      body: { entitlement: 'ocr_pages_monthly', units, idempotency_key: key },
    });
  return { user, other, grant, operator, path, consume };
}
it('enforces tenant isolation, rejects forged limits and atomically bounds concurrent usage', async () => {
  const { user, other, path, consume } = await setup();
  expect((await env.call('GET', path)).status).toBe(401);
  expect((await env.call('GET', path, { token: other.token })).status).toBe(404);
  expect((await consume('cross-tenant-request', 3, other.token)).status).toBe(404);
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: {
          entitlement: 'ocr_pages_monthly',
          units: 3,
          idempotency_key: 'forged-limit-request',
          limit: 999,
        },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: {
          entitlement: 'ocr_pages_monthly',
          units: 1,
          idempotency_key: 'newline-operation-key\n',
        },
      })
    ).status,
  ).toBe(400);
  const results = await Promise.all([
    consume('first-operation-key'),
    consume('second-operation-key'),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
  const usage = (await env.call('GET', path, { token: user.token })).body;
  expect(usage.items).toEqual([
    { entitlement: 'ocr_pages_monthly', limit: 5, used: 3, remaining: 2 },
  ]);
  expect((await consume('zero-units-request', 0)).status).toBe(400);
});
it('deduplicates retries, rejects changed payloads and never charges old requests in a new month', async () => {
  const { user, path, consume } = await setup();
  const results = await Promise.all([consume('same-operation-key'), consume('same-operation-key')]);
  expect(results.map((r) => r.status)).toEqual([200, 200]);
  expect(results[0]!.body).toEqual(results[1]!.body);
  expect((await consume('same-operation-key', 2)).status).toBe(409);
  expect((await env.call('GET', path, { token: user.token })).body.items[0].used).toBe(3);
  env.clock.advance(32 * 86400000);
  // Re-login because ordinary sessions expire before the next month.
  user.token = await env.login('quota@example.test');
  expect((await consume('same-operation-key')).body.period).toBe('2026-03');
  expect((await env.call('GET', path, { token: user.token })).body.items[0].used).toBe(0);
  expect((await consume('new-month-operation')).status).toBe(200);
  const events = await env.c.audit.list({ action: 'quota.consumed' });
  expect(events).toHaveLength(2);
  expect(JSON.stringify(events)).not.toContain('same-operation-key');
});
it('uses current plan limits, preserves charges on downgrade, and refuses suspended licenses', async () => {
  const { user, grant, operator, path, consume } = await setup();
  expect((await consume('before-downgrade-key')).status).toBe(200);
  await env.call('PATCH', `/v1/admin/plans/${grant.planId}`, {
    token: operator,
    body: { entitlements: { ocr_pages_monthly: 2 }, reason: 'Downgrade allowance' },
  });
  expect((await env.call('GET', path, { token: user.token })).body.items[0]).toMatchObject({
    limit: 2,
    used: 3,
    remaining: 0,
  });
  expect((await consume('after-downgrade-key', 1)).status).toBe(409);
  const switched = await env.call('POST', `/v1/admin/products/${grant.productId}/plans`, {
    token: operator,
    body: {
      code: 'switched-quota',
      tier: 'standard',
      entitlements: { ocr_pages_monthly: 7 },
      capabilities: [],
      device_limit: 3,
      reason: 'Switch commercial plan',
    },
  });
  expect(switched.status).toBe(201);
  expect(
    (
      await env.call(
        'PATCH',
        `/v1/admin/organizations/${user.orgId}/subscriptions/${grant.subId}`,
        { token: operator, body: { plan_id: switched.body.id, reason: 'Apply current plan' } },
      )
    ).status,
  ).toBe(200);
  expect((await consume('after-plan-switch-key', 4)).status).toBe(200);
  expect((await env.call('GET', path, { token: user.token })).body.items[0]).toMatchObject({
    limit: 7,
    used: 7,
    remaining: 0,
  });
  await env.call(
    'POST',
    `/v1/admin/organizations/${user.orgId}/licenses/${grant.licenseId}/suspend`,
    { token: operator, body: { reason: 'Suspend test license' } },
  );
  expect((await consume('before-downgrade-key')).status).toBe(403);
});
it('refuses missing or removed quotas and does not consume for an expired subscription', async () => {
  const { user, path, grant, operator } = await setup();
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: {
          entitlement: 'unknown_monthly',
          units: 1,
          idempotency_key: 'unknown-operation-key',
        },
      })
    ).status,
  ).toBe(403);
  await env.call('PATCH', `/v1/admin/organizations/${user.orgId}/subscriptions/${grant.subId}`, {
    token: operator,
    body: { current_period_end: '2026-02-28T00:00:00Z', reason: 'Expired subscription test' },
  });
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: {
          entitlement: 'ocr_pages_monthly',
          units: 1,
          idempotency_key: 'expired-operation-key',
        },
      })
    ).status,
  ).toBe(403);
  expect((await env.call('GET', path, { token: user.token })).body.items[0].used).toBe(0);
});

it('hides canary licenses from quota reads and consumption', async () => {
  const { user, grant, operator } = await setup();
  const issued = await env.call('POST', `/v1/admin/organizations/${user.orgId}/licenses`, {
    token: operator,
    body: {
      product_id: grant.productId,
      plan_id: grant.planId,
      kind: 'canary',
      reason: 'Canary isolation test',
    },
  });
  expect(issued.status).toBe(201);
  const path = `/v1/organizations/${user.orgId}/licenses/${issued.body.license.id}/usage`;
  expect((await env.call('GET', path, { token: user.token })).status).toBe(404);
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: {
          entitlement: 'ocr_pages_monthly',
          units: 1,
          idempotency_key: 'canary-operation-key',
        },
      })
    ).status,
  ).toBe(404);
});
