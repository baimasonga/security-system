import { afterEach, expect, it, vi } from 'vitest';
import { createApkDistributionReader } from '../src/integrations/apk-distribution.ts';
import { makeEnv, type Env } from './harness.ts';
const asset = {
  id: 123,
  name: 'rokela-pdf.apk',
  state: 'uploaded',
  download_count: 17,
  size: 100,
  created_at: '2026-10-25T00:00:00Z',
  updated_at: '2026-10-25T00:00:00Z',
  browser_download_url:
    'https://github.com/baimasonga/Rokelapdf-online/releases/download/android/rokela-pdf.apk',
};
const response = (assets = [asset]) =>
  Response.json({ tag_name: 'android', draft: false, assets, body: 'PRIVATE provider text' });
let env: Env | undefined;
afterEach(async () => {
  vi.unstubAllGlobals();
  await env?.app.close();
  env = undefined;
});
it('reports only current asset metadata, with fixed destination and shared cache', async () => {
  let now = 0;
  const request = vi.fn<typeof fetch>().mockImplementation(async () => response());
  const read = createApkDistributionReader(request, () => now);
  const [a, b] = await Promise.all([read(), read()]);
  expect(a).toEqual(b);
  expect(a).toMatchObject({ status: 'available', downloads: 17, asset_id: 123 });
  expect(JSON.stringify(a)).not.toContain('PRIVATE');
  await read();
  expect(request).toHaveBeenCalledTimes(1);
  expect(request.mock.calls[0]?.[0]).toBe(
    'https://api.github.com/repos/baimasonga/Rokelapdf-online/releases/tags/android',
  );
  expect(request.mock.calls[0]?.[1]).toMatchObject({ redirect: 'error', credentials: 'omit' });
  now = 300001;
  await read();
  expect(request).toHaveBeenCalledTimes(2);
});
it.each(
  [
    [],
    [asset, asset],
    [{ ...asset, download_count: -1 }],
    [{ ...asset, download_count: 1.5 }],
    [{ ...asset, browser_download_url: 'https://attacker.test/private' }],
    [{ ...asset, state: 'new' }],
  ].map((assets) => ({ assets })),
)('refuses missing, conflicting or invalid asset evidence %#', async ({ assets }) => {
  const read = createApkDistributionReader(async () => response(assets));
  expect(await read()).toMatchObject({ status: 'unavailable' });
  expect(await read()).not.toHaveProperty('downloads');
});
it('bounds response bytes and never echoes network failures', async () => {
  for (const request of [
    async () =>
      new Response('x'.repeat(262145), { headers: { 'content-type': 'application/json' } }),
    async () => {
      throw new Error('PRIVATE token');
    },
    async () => new Response('PRIVATE', { status: 429 }),
  ]) {
    const result = await createApkDistributionReader(request)();
    expect(result.status).toBe('unavailable');
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
  }
});
it('protects the route before outbound requests and rejects destination input', async () => {
  const request = vi.fn<typeof fetch>().mockImplementation(async () => response());
  vi.stubGlobal('fetch', request);
  env = await makeEnv();
  expect((await env.call('GET', '/v1/admin/mobile-distribution')).status).toBe(401);
  const user = await env.register('apk-reader@example.test');
  expect(
    (await env.call('GET', '/v1/admin/mobile-distribution', { token: user.token })).status,
  ).toBe(403);
  expect(request).not.toHaveBeenCalled();
  const token = await env.operatorToken();
  expect(
    (await env.call('GET', '/v1/admin/mobile-distribution?url=https://attacker.test', { token }))
      .status,
  ).toBe(400);
  expect(request).not.toHaveBeenCalled();
  const result = await env.call('GET', '/v1/admin/mobile-distribution', { token });
  expect(result.status).toBe(200);
  expect(result.body.downloads).toBe(17);
});
