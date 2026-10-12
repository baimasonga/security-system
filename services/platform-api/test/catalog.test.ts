import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());
it('catalog browsing requires a session and exposes no tenant secrets', async () => {
  env = await makeEnv();
  const user = await env.register('reader@example.test');
  const issued = await env.provision(user.orgId);
  expect((await env.call('GET', '/v1/catalog/products')).status).toBe(401);
  const products = await env.call('GET', '/v1/catalog/products', { token: user.token });
  expect(products.status).toBe(200);
  expect(products.body.items.some((p: { id: string }) => p.id === issued.productId)).toBe(true);
  const plans = await env.call('GET', `/v1/catalog/products/${issued.productId}/plans`, {
    token: user.token,
  });
  expect(plans.status).toBe(200);
  expect(
    (
      await env.call('GET', '/v1/catalog/products/prd_000000000000000000000000/plans', {
        token: user.token,
      })
    ).status,
  ).toBe(404);
  expect(plans.body.items.some((p: { id: string }) => p.id === issued.planId)).toBe(true);
  expect(JSON.stringify(products.body) + JSON.stringify(plans.body)).not.toContain(
    issued.licenseKey,
  );
});
