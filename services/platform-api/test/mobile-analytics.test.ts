import { mobileBatch } from '../src/mobile-analytics.ts';
import { randomUUID } from 'node:crypto';
import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
import { mobileClientIp, createCountryLookup } from '../src/integrations/mobile-country.ts';
let env: Env;
afterEach(async () => env?.app.close());
const batch = () => ({
  installation_id: randomUUID(),
  events: [
    {
      id: randomUUID(),
      occurred_at: '2026-03-01T00:00:00Z',
      feature: 'app_open',
      app_version: '1.2.3',
      os_major: 14,
      device_class: 'phone',
    },
  ],
});
const path = '/v1/mobile/rokela-pdf/events';
it('commits reports, deduplicates concurrent retries and exposes only aggregate operator reads', async () => {
  env = await makeEnv();
  const body = batch();
  const results = await Promise.all(
    Array.from({ length: 20 }, () => env.call('POST', path, { body })),
  );
  expect(results.every((r) => r.status === 202)).toBe(true);
  expect((await env.call('GET', '/v1/admin/mobile-analytics')).status).toBe(401);
  const user = await env.register('mobile-test@example.test');
  expect((await env.call('GET', '/v1/admin/mobile-analytics', { token: user.token })).status).toBe(
    403,
  );
  const summary = await env.call('GET', '/v1/admin/mobile-analytics', {
    token: await env.operatorToken(),
  });
  expect(summary.body).toMatchObject({
    reports: 1,
    active_installations_30d: 1,
    country_lookup_configured: false,
  });
  expect(JSON.stringify(summary.body)).not.toContain(body.installation_id);
  expect(summary.body.countries).toEqual([]);
  expect(summary.body.features).toContainEqual({ label: 'app_open', events: 1, installations: 1 });
});
it('rolls back a batch containing conflicting event content', async () => {
  env = await makeEnv();
  const body = batch();
  await env.call('POST', path, { body });
  const changed = {
    ...body,
    events: [
      { ...body.events[0], id: randomUUID() },
      { ...body.events[0], feature: 'scan' },
    ],
  };
  expect((await env.call('POST', path, { body: changed })).status).toBe(409);
  expect((await env.c.mobileAnalytics.summary()).reports).toBe(1);
});
it('rejects GPS, claimed country, arbitrary text, stale events, oversized bodies and batches', async () => {
  env = await makeEnv();
  for (const body of [
    { ...batch(), country: 'SL' },
    { ...batch(), latitude: 8 },
    { ...batch(), events: [{ ...batch().events[0], feature: 'private document.pdf' }] },
    { ...batch(), events: [{ ...batch().events[0], occurred_at: '2025-01-01T00:00:00Z' }] },
    { ...batch(), events: Array.from({ length: 21 }, () => batch().events[0]) },
  ])
    expect((await env.call('POST', path, { body })).status).toBe(400);
  expect(
    (await env.call('POST', path, { body: { ...batch(), extra: 'x'.repeat(17000) } })).status,
  ).toBe(413);
  expect((await env.c.mobileAnalytics.summary()).reports).toBe(0);
});
it('uses only configured ingress hops and fails country lookup closed', async () => {
  expect(mobileClientIp('1.1.1.1, 8.8.8.8', 0)).toBe('');
  expect(mobileClientIp('1.1.1.1, 8.8.8.8', 1)).toBe('8.8.8.8');
  expect(mobileClientIp('1.1.1.1, 8.8.8.8', 2)).toBe('1.1.1.1');
  expect(mobileClientIp('private', 1)).toBe('');
  expect(mobileClientIp('8.8.8.8', 2)).toBe('');
  expect(await createCountryLookup()('8.8.8.8')).toBeNull();
  expect(await createCountryLookup('/missing/country.mmdb')('8.8.8.8')).toBeNull();
});
it('allows only the native origin, and ignored country headers cannot fabricate geography', async () => {
  env = await makeEnv();
  expect(
    (
      await env.call('OPTIONS', path, {
        headers: { origin: 'https://localhost', 'access-control-request-method': 'POST' },
      })
    ).status,
  ).toBe(204);
  expect(
    (await env.call('POST', path, { body: batch(), headers: { origin: 'https://attacker.test' } }))
      .status,
  ).toBe(403);
  const response = await env.call('POST', path, {
    body: batch(),
    headers: { origin: 'https://localhost', 'cf-ipcountry': 'SL', 'x-forwarded-for': '8.8.8.8' },
  });
  expect(response.status).toBe(202);
  expect(response.headers['access-control-allow-origin']).toBe('https://localhost');
  expect((await env.c.mobileAnalytics.summary()).countries).toEqual([]);
});
it('hides rare countries and expires reports from summaries and storage', async () => {
  env = await makeEnv();
  for (let i = 0; i < 5; i++) await env.c.mobileAnalytics.accept(mobileBatch.parse(batch()), 'SL');
  await env.c.mobileAnalytics.accept(mobileBatch.parse(batch()), 'GB');
  expect((await env.c.mobileAnalytics.summary()).countries).toEqual([
    { label: 'SL', events: 5, installations: 5 },
  ]);
  env.clock.advance(31 * 86400000);
  expect((await env.c.mobileAnalytics.summary()).reports).toBe(0);
  expect(await env.c.mobileAnalytics.retain()).toBe(6);
  expect(await env.c.mobileAnalytics.retain()).toBe(0);
});

it('uses configured ingress hops for local lookup without trusting a country header', async () => {
  const seen: string[] = [];
  env = await makeEnv({
    config: { mobileProxyHops: 1, mobileCountryDatabase: '/fixture/country.mmdb' },
    container: {
      mobileCountryLookup: async (ip) => {
        seen.push(ip);
        return ip === '8.8.8.8' ? 'US' : null;
      },
    },
  });
  for (let i = 0; i < 5; i++)
    expect(
      (
        await env.call('POST', path, {
          body: batch(),
          headers: { 'x-forwarded-for': '1.1.1.1, 8.8.8.8', 'cf-ipcountry': 'SL' },
        })
      ).status,
    ).toBe(202);
  expect(seen).toEqual(Array(5).fill('8.8.8.8'));
  const summary = await env.call('GET', '/v1/admin/mobile-analytics', {
    token: await env.operatorToken(),
  });
  expect(summary.body.country_lookup_configured).toBe(true);
  expect(summary.body.countries).toEqual([{ label: 'US', events: 5, installations: 5 }]);
});
