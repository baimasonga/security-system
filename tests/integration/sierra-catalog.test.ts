import { afterEach, expect, it, vi } from 'vitest';
import { MemorySecureStore, TrustPlatformClient } from '@trust/sdk-core';
import { makeEnv, DAY, type Env } from '../../services/platform-api/test/harness.ts';
import {
  catalogHttpRequest,
  provisionSierraCatalog,
  type CatalogRequest,
} from '../../tools/sierra-catalog.ts';
let env: Env;
afterEach(async () => env?.app.close());
const options = {
  planCode: 'standard',
  tier: 'standard',
  deviceLimit: 2,
  reason: 'publisher catalog setup',
};
async function setup(operator = true) {
  env = await makeEnv();
  const token = operator
    ? await env.operatorToken()
    : (await env.register('customer@example.test')).token;
  const calls: Array<{ method: string; path: string }> = [];
  const request: CatalogRequest = async (method, path, body) => {
    calls.push({ method, path });
    const result = await env.call(method, path, { token, body });
    if (result.status >= 400) throw new Error(`API HTTP ${result.status}`);
    return result.body;
  };
  return { request, calls, token };
}
it('previews missing catalog without writing, then creates audited compatible catalog and repeats without writes', async () => {
  const s = await setup();
  expect(await provisionSierraCatalog(s.request, options)).toMatchObject({
    ready: false,
    missing: ['product', 'plan'],
  });
  expect(s.calls.every((c) => c.method === 'GET')).toBe(true);
  const applied = await provisionSierraCatalog(s.request, { ...options, apply: true });
  expect(applied).toMatchObject({ ready: true, missing: [] });
  const products = await env.call('GET', '/v1/catalog/products', { token: s.token });
  const product = products.body.items.find((p: { code: string }) => p.code === 'sierra-business');
  const plans = await env.call('GET', `/v1/catalog/products/${product.id}/plans`, {
    token: s.token,
  });
  expect(plans.body.items).toEqual([
    expect.objectContaining({
      code: 'standard',
      tier: 'standard',
      entitlements: { business_write: true },
      device_limit: 2,
    }),
  ]);
  const audit = await env.call('GET', '/v1/admin/audit', { token: s.token });
  for (const action of ['product.created', 'plan.created'])
    expect(audit.body.items).toContainEqual(
      expect.objectContaining({ action, reason: options.reason }),
    );
  s.calls.length = 0;
  expect(await provisionSierraCatalog(s.request, { ...options, apply: true })).toMatchObject({
    ready: true,
  });
  expect(s.calls.every((c) => c.method === 'GET')).toBe(true);
});
it('refuses customer sessions before catalog mutations', async () => {
  const s = await setup(false);
  await expect(provisionSierraCatalog(s.request, { ...options, apply: true })).rejects.toThrow(
    /operator/,
  );
  expect(s.calls).toEqual([{ method: 'GET', path: '/v1/auth/me' }]);
});
it.each([false, true])(
  'recovers partial catalog setup without duplicate creation (plan committed: %s)',
  async (committed) => {
    const s = await setup();
    const interrupted: CatalogRequest = async (method, path, body) => {
      if (method === 'POST' && path.endsWith('/plans')) {
        if (committed) await s.request(method, path, body);
        throw new Error('interrupted setup');
      }
      return s.request(method, path, body);
    };
    await expect(provisionSierraCatalog(interrupted, { ...options, apply: true })).rejects.toThrow(
      'interrupted',
    );
    expect((await provisionSierraCatalog(s.request, options)).ready).toBe(committed);
    expect((await provisionSierraCatalog(s.request, { ...options, apply: true })).ready).toBe(true);
    expect(
      s.calls.filter((c) => c.method === 'POST' && c.path === '/v1/admin/products'),
    ).toHaveLength(1);
    expect(s.calls.filter((c) => c.method === 'POST' && c.path.endsWith('/plans'))).toHaveLength(1);
  },
);
it.each(['disabled', 'numeric', 'tier', 'devices'])(
  'refuses mismatched existing commercial access (%s)',
  async (mismatch) => {
    const s = await setup();
    await provisionSierraCatalog(s.request, { ...options, apply: true });
    const product = (await env.call('GET', '/v1/catalog/products', { token: s.token })).body
      .items[0];
    const plan = (
      await env.call('GET', `/v1/catalog/products/${product.id}/plans`, { token: s.token })
    ).body.items[0];
    if (mismatch === 'disabled' || mismatch === 'numeric')
      await env.call('PATCH', `/v1/admin/plans/${plan.id}`, {
        token: s.token,
        body: {
          entitlements: { business_write: mismatch === 'numeric' ? 1 : false },
          reason: 'restrict plan',
        },
      });
    s.calls.length = 0;
    await expect(
      provisionSierraCatalog(s.request, {
        ...options,
        ...(mismatch === 'tier' ? { tier: 'professional' } : {}),
        ...(mismatch === 'devices' ? { deviceLimit: 3 } : {}),
        apply: true,
      }),
    ).rejects.toThrow(/mismatch/);
    expect(s.calls.every((c) => c.method === 'GET')).toBe(true);
  },
);
it('validates commercial settings before any request', async () => {
  const s = await setup();
  for (const change of [
    { reason: '' },
    { deviceLimit: 0 },
    { planCode: '../other' },
    { tier: 'invented' },
  ])
    await expect(provisionSierraCatalog(s.request, { ...options, ...change })).rejects.toThrow();
  expect(s.calls).toEqual([]);
});
it('restricts operator transport to its origin and sanitizes provider errors', async () => {
  const fetcher = vi.fn<typeof fetch>(async () => {
    throw new Error('private-token-or-provider-body');
  });
  for (const origin of [
    'http://remote.example',
    'https://operator:password@api.example',
    'https://api.example/path',
    'https://api.example?token=x',
    'https://api.example/#x',
  ])
    expect(() => catalogHttpRequest(origin, 'fixture-token', false, fetcher)).toThrow();
  const request = catalogHttpRequest('https://api.example/', 'fixture-token', false, fetcher);
  await expect(request('GET', 'https://other.example/v1/auth/me')).rejects.toThrow(/path/);
  expect(fetcher).not.toHaveBeenCalled();
  await expect(request('GET', '/v1/auth/me')).rejects.toThrow('API request failed');
  expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
    redirect: 'error',
    headers: { authorization: 'Bearer fixture-token' },
  });
});
it('provisions and exercises Sierra Business licensing over HTTP through renewal, expiry, suspension and revocation', async () => {
  env = await makeEnv();
  await env.app.listen({ host: '127.0.0.1', port: 0 });
  const address = env.app.server.address();
  if (!address || typeof address !== 'object') throw new Error('test server unavailable');
  const origin = `http://127.0.0.1:${address.port}/`;
  const operator = await env.operatorToken();
  const catalog = await provisionSierraCatalog(catalogHttpRequest(origin, operator, true), {
    ...options,
    apply: true,
  });
  const customer = await env.register('sierra-customer@example.test');
  const until = () => new Date(env.clock.now().getTime() + 30 * DAY).toISOString();
  const sub = await env.call('POST', `/v1/admin/organizations/${customer.orgId}/subscriptions`, {
    token: operator,
    body: {
      plan_id: catalog.planId,
      status: 'active',
      current_period_end: until(),
      reason: options.reason,
    },
  });
  expect(sub.status).toBe(201);
  const issued = await env.call('POST', `/v1/admin/organizations/${customer.orgId}/licenses`, {
    token: operator,
    body: {
      product_id: catalog.productId,
      plan_id: catalog.planId,
      kind: 'subscription',
      subscription_id: sub.body.id,
      reason: options.reason,
    },
  });
  expect(issued.status).toBe(201);
  const trust = (await env.call('GET', '/v1/keys/trust-bundle')).body;
  const client = new TrustPlatformClient({
    baseUrl: origin,
    productCode: 'sierra-business',
    trust,
    store: new MemorySecureStore(),
    now: env.clock.now,
  });
  expect((await client.activate(customer.token, issued.body.license_key)).state).toBe('valid');
  expect((await client.getEntitlements()).entitlements.business_write === true).toBe(true);
  env.clock.advance(31 * DAY);
  expect((await client.getEntitlements()).entitlements.business_write === true).toBe(false);
  await expect(client.refreshLease()).rejects.toThrow();
  const freshOperator = await env.login('operator@example.test');
  expect(
    (
      await env.call(
        'PATCH',
        `/v1/admin/organizations/${customer.orgId}/subscriptions/${sub.body.id}`,
        {
          token: freshOperator,
          body: { current_period_end: until(), reason: 'renew agreed paid period' },
        },
      )
    ).status,
  ).toBe(200);
  expect((await client.refreshLease()).state).toBe('valid');
  expect((await client.getEntitlements()).entitlements.business_write === true).toBe(true);
  const statePath = `/v1/admin/organizations/${customer.orgId}/licenses/${issued.body.license.id}`;
  expect(
    (
      await env.call('POST', statePath + '/suspend', {
        token: freshOperator,
        body: { reason: 'suspend for review' },
      })
    ).status,
  ).toBe(200);
  await expect(client.refreshLease()).rejects.toThrow();
  expect(
    (
      await env.call('POST', statePath + '/reinstate', {
        token: freshOperator,
        body: { reason: 'review completed' },
      })
    ).status,
  ).toBe(200);
  expect((await client.refreshLease()).state).toBe('valid');
  expect(
    (
      await env.call('POST', statePath + '/revoke', {
        token: freshOperator,
        body: { reason: 'close test license' },
      })
    ).status,
  ).toBe(200);
  await expect(client.refreshLease()).rejects.toMatchObject({ code: 'activation_not_found' });
  // The Node SDK retains offline access through its documented bounded five-minute clock skew.
  const expiry = (await client.getEntitlements()).leaseExpiresAt;
  expect(expiry).not.toBeNull();
  env.clock.set(new Date(expiry!.getTime() + 301_000));
  expect((await client.getEntitlements()).entitlements.business_write === true).toBe(false);
});
