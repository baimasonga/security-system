import { createHmac } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import type { CheckoutProvider } from '../src/integrations/billing.ts';
let env: Env;
afterEach(async () => env?.app.close());
const price = 'pri_' + 'a'.repeat(26),
  txn = 'txn_' + 'b'.repeat(26),
  psub = 'sub_' + 'c'.repeat(26),
  secret = 'test-webhook-secret-' + 'x'.repeat(32);
async function setup(fail = false, trustProxy = false, team = false) {
  const prices: Record<string, string> = {};
  let intent = '';
  const provider: CheckoutProvider = {
    createCheckout: vi.fn(async (request) => {
      intent = request.intentId;
      if (fail) throw new Error('provider secret');
      return {
        transactionId: txn,
        url: 'https://pay.example/checkout?_ptxn=' + txn,
        status: 'draft',
      };
    }),
    getCheckout: vi.fn(async (_id, _request) => ({
      transactionId: txn,
      url: 'https://pay.example/checkout?_ptxn=' + txn,
      status: 'ready',
    })),
  };
  env = await makeEnv({
    config: {
      trustProxy,
      billing: {
        apiKey: 'test-key',
        webhookSecret: secret,
        environment: 'sandbox',
        paymentUrl: 'https://pay.example/checkout',
        prices,
      },
    },
    checkoutProvider: provider,
  });
  const user = await env.register('buyer@example.test'),
    other = await env.register('other@example.test'),
    grant = await env.provision(
      team
        ? (
            await env.call('POST', '/v1/organizations', {
              token: user.token,
              body: { name: 'Billing team' },
            })
          ).body.id
        : user.orgId,
    );
  if (team)
    user.orgId = (
      await env.c.auth.listOrganizations(await env.c.auth.authenticate(user.token))
    ).find((org) => org.kind === 'team')!.id;
  prices[grant.planId] = price;
  const path = `/v1/organizations/${user.orgId}/licenses/${grant.licenseId}/checkout`;
  const checkout = (key = 'checkout-request-001', token = user.token) =>
    env.call('POST', path, { token, body: { plan_id: grant.planId, idempotency_key: key } });
  const event = (over: Record<string, unknown> = {}) => ({
    event_id: 'evt_' + 'd'.repeat(26),
    event_type: 'transaction.completed',
    occurred_at: env.clock.now().toISOString(),
    data: {
      id: txn,
      status: 'completed',
      collection_mode: 'automatic',
      subscription_id: psub,
      custom_data: { trust_checkout_id: intent },
      items: [{ price: { id: price }, quantity: 1 }],
      billing_period: { ends_at: '2026-04-01T00:00:00.000Z' },
    },
    ...over,
  });
  const webhook = async (body: unknown, signatureValid = true) => {
    const raw = JSON.stringify(body),
      ts = String(Math.floor(env.clock.now().getTime() / 1000));
    return env.call('POST', '/v1/billing/webhooks/paddle', {
      body: raw,
      headers: {
        'content-type': 'application/json',
        'paddle-signature': `ts=${ts};h1=${signatureValid ? createHmac('sha256', secret).update(`${ts}:${raw}`).digest('hex') : '0'.repeat(64)}`,
      },
    });
  };
  return { provider, user, other, grant, path, checkout, event, webhook };
}
it('authorizes checkout, forbids arbitrary pricing and creates one provider transaction under concurrent retries', async () => {
  const s = await setup();
  expect((await s.checkout('other-checkout-key', s.other.token)).status).toBe(404);
  expect(
    (
      await env.call('POST', s.path, {
        token: s.user.token,
        body: { plan_id: s.grant.planId, idempotency_key: 'checkout-request-001', price_id: price },
      })
    ).status,
  ).toBe(400);
  const replies = await Promise.all([s.checkout(), s.checkout()]);
  expect(replies.every((r) => r.status === 200)).toBe(true);
  expect(replies[0]!.body.id).toBe(replies[1]!.body.id);
  expect(s.provider.createCheckout).toHaveBeenCalledTimes(1);
  expect((await s.checkout('different-operation')).status).toBe(409);
  expect((await env.call('GET', s.path, { token: s.other.token })).status).toBe(404);
});
it('requires a signed mapped completion, atomically applies payment, and makes replays harmless', async () => {
  const s = await setup();
  await s.checkout();
  const e = s.event();
  expect((await s.webhook(e, false)).status).toBe(403);
  expect((await s.webhook(e)).status).toBe(200);
  expect((await s.webhook(e)).status).toBe(200);
  const license = await env.call('GET', s.path, { token: s.user.token });
  expect(license.body.current_period_end).toBe('2026-04-01T00:00:00.000Z');
  const changed = {
    ...e,
    data: { ...(e.data as object), billing_period: { ends_at: '2026-05-01T00:00:00.000Z' } },
  };
  expect((await s.webhook(changed)).status).toBe(409);
});
it('persists uncertain outcomes and does not retry a provider submission', async () => {
  const s = await setup(true);
  expect((await s.checkout()).body.status).toBe('uncertain');
  expect((await s.checkout()).body.status).toBe('uncertain');
  expect(s.provider.createCheckout).toHaveBeenCalledTimes(1);
});
it('rejects cross-intent or price-substituted signed completions', async () => {
  const s = await setup();
  await s.checkout();
  const e = s.event();
  for (const data of [
    { ...e.data, custom_data: { trust_checkout_id: 'bco_unknown' } },
    { ...e.data, items: [{ price: { id: 'pri_' + 'e'.repeat(26) }, quantity: 1 }] },
  ])
    expect((await s.webhook({ ...e, data })).status).not.toBe(200);
});
it('ignores older subscription events and applies cancellation without reviving revoked licenses', async () => {
  const s = await setup();
  await s.checkout();
  expect((await s.webhook(s.event())).status).toBe(200);
  env.clock.advance(1000);
  const data = {
    id: psub,
    status: 'canceled',
    custom_data: (s.event().data as { custom_data: object }).custom_data,
    items: [{ price: { id: price }, quantity: 1 }],
    current_billing_period: null,
  };
  const canceled = s.event({
    event_id: 'evt_' + 'e'.repeat(26),
    event_type: 'subscription.canceled',
    data,
  });
  expect((await s.webhook(canceled)).status).toBe(200);
  const old = s.event({
    event_id: 'evt_' + 'f'.repeat(26),
    event_type: 'subscription.updated',
    occurred_at: '2026-03-01T00:00:00.000Z',
    data: {
      ...data,
      status: 'active',
      current_billing_period: { ends_at: '2026-04-01T00:00:00.000Z' },
    },
  });
  expect((await s.webhook(old)).status).toBe(200);
  const license = await env.call('GET', s.path, { token: s.user.token });
  expect(license.body.subscription_status).toBe('canceled');
});

it('processes concurrent event delivery with a monotonic subscription watermark', async () => {
  const s = await setup();
  await s.checkout();
  expect((await s.webhook(s.event())).status).toBe(200);
  const data = {
    id: psub,
    status: 'active',
    custom_data: (s.event().data as { custom_data: object }).custom_data,
    items: [{ price: { id: price }, quantity: 1 }],
    current_billing_period: { ends_at: '2026-05-01T00:00:00.000Z' },
  };
  const events = Array.from({ length: 20 }, (_, i) =>
    s.event({
      event_id: 'evt_' + i.toString(16).padStart(26, 'a'),
      event_type: 'subscription.updated',
      occurred_at: new Date(env.clock.now().getTime() + (i + 1) * 1000).toISOString(),
      data,
    }),
  );
  const responses = await Promise.all(events.reverse().map((event) => s.webhook(event)));
  expect(responses.every((r) => r.status === 200)).toBe(true);
  const cancel = s.event({
    event_id: 'evt_' + '9'.repeat(26),
    event_type: 'subscription.canceled',
    occurred_at: new Date(env.clock.now().getTime() + 19000).toISOString(),
    data: { ...data, status: 'canceled', current_billing_period: null },
  });
  expect((await s.webhook(cancel)).status).toBe(200);
  expect((await env.call('GET', s.path, { token: s.user.token })).body.subscription_status).toBe(
    'active',
  );
});
it('requires operator reconciliation for unknown transaction outcomes and preserves license revocation', async () => {
  const s = await setup(true);
  await s.checkout();
  const reconcile = `/v1/admin/organizations/${s.user.orgId}/licenses/${s.grant.licenseId}/checkout/reconcile`;
  expect(
    (
      await env.call('POST', reconcile, {
        token: s.user.token,
        body: { transaction_id: txn, reason: 'Resolve uncertain checkout' },
      })
    ).status,
  ).toBe(403);
  const operator = await env.operatorToken();
  expect(
    (await env.call('POST', reconcile, { token: operator, body: { transaction_id: txn } })).status,
  ).toBe(400);
  expect(
    (
      await env.call('POST', reconcile, {
        token: operator,
        body: { transaction_id: txn, reason: 'Resolve uncertain checkout' },
      })
    ).status,
  ).toBe(200);
  expect(
    (
      await env.call(
        'POST',
        `/v1/admin/organizations/${s.user.orgId}/licenses/${s.grant.licenseId}/revoke`,
        { token: operator, body: { reason: 'Security revocation' } },
      )
    ).status,
  ).toBe(200);
  expect((await s.webhook(s.event())).status).toBe(200);
  expect(
    (
      await env.call('GET', `/v1/organizations/${s.user.orgId}/licenses/${s.grant.licenseId}`, {
        token: s.user.token,
      })
    ).body.state,
  ).toBe('revoked');
});
it('rejects equal-time conflicting notifications, expired paid periods and mismatched event statuses', async () => {
  const s = await setup();
  await s.checkout();
  const e = s.event();
  expect(
    (
      await s.webhook({
        ...e,
        data: { ...e.data, billing_period: { ends_at: '2026-02-01T00:00:00.000Z' } },
      })
    ).status,
  ).toBe(409);
  expect((await s.webhook(e)).status).toBe(200);
  const data = {
    id: psub,
    status: 'active',
    custom_data: (e.data as { custom_data: object }).custom_data,
    items: [{ price: { id: price }, quantity: 1 }],
    current_billing_period: { ends_at: '2026-04-01T00:00:00.000Z' },
  };
  expect(
    (
      await s.webhook(
        s.event({ event_id: 'evt_' + '0'.repeat(26), event_type: 'subscription.canceled', data }),
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await s.webhook(
        s.event({ event_id: 'evt_' + '0'.repeat(26), event_type: 'subscription.updated', data }),
      )
    ).status,
  ).toBe(409);
});

it('isolates payment scripts from the portal and exposes only an explicit public client token', async () => {
  const s = await setup();
  const page = await env.call('GET', '/checkout', { headers: { host: 'pay.example' } }),
    portal = await env.call('GET', '/');
  expect(String(page.headers['content-security-policy'])).toContain('https://cdn.paddle.com');
  expect(String(portal.headers['content-security-policy'])).not.toContain('paddle.com');
  expect((await env.call('GET', '/v1/billing/checkout-options')).status).toBe(503);
  env.c.config.billing!.clientToken = 'test_' + 'p'.repeat(32);
  const options = await env.call('GET', '/v1/billing/checkout-options');
  expect(options.body).toEqual({ environment: 'sandbox', client_token: 'test_' + 'p'.repeat(32) });
  expect(JSON.stringify(options.body)).not.toContain('test-key');
  expect(JSON.stringify(options.body)).not.toContain(secret);
  expect((await s.checkout()).status).toBe(200);
});

it('never admits Paddle scripts on the account origin or serves the account portal on the payment host', async () => {
  await setup(false, true);
  env.c.config.billing!.portalOrigin = 'https://accounts.example';
  expect(
    (await env.call('GET', '/checkout', { headers: { host: 'accounts.example' } })).status,
  ).toBe(404);
  expect(
    (
      await env.call('GET', '/checkout', {
        headers: {
          host: 'accounts.example',
          'x-forwarded-host': 'pay.example',
          'x-forwarded-proto': 'https',
        },
      })
    ).status,
  ).toBe(404);
  const payment = await env.call('GET', '/checkout', { headers: { host: 'pay.example' } });
  expect(payment.status).toBe(200);
  expect((await env.call('GET', '/', { headers: { host: 'pay.example' } })).status).toBe(404);
  expect((await env.call('GET', '/device.mjs', { headers: { host: 'pay.example' } })).status).toBe(
    404,
  );
  expect((await env.call('GET', '/', { headers: { host: 'accounts.example' } })).status).toBe(200);
});

it('protects payment links from ordinary organization members while preserving license reads', async () => {
  const s = await setup(false, false, true);
  expect(
    (
      await env.call('POST', `/v1/organizations/${s.user.orgId}/members`, {
        token: s.user.token,
        body: { email: 'other@example.test', role: 'member' },
      })
    ).status,
  ).toBe(201);
  await s.checkout();
  expect((await env.call('GET', s.path, { token: s.other.token })).status).toBe(403);
  expect((await s.checkout('member-checkout-request', s.other.token)).status).toBe(403);
  expect(
    (
      await env.call('GET', `/v1/organizations/${s.user.orgId}/licenses/${s.grant.licenseId}`, {
        token: s.other.token,
      })
    ).status,
  ).toBe(200);
  expect(s.provider.createCheckout).toHaveBeenCalledTimes(1);
});
