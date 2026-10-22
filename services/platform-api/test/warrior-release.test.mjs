import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { checkRelease } from '../../../tools/check-warrior-release.mjs';

const origin = 'https://trustplatform-api-production.up.railway.app';
const fixture = async (url) => {
  const path = new URL(url).pathname;
  if (path === '/healthz' || path === '/readyz')
    return new globalThis.Response(
      JSON.stringify({ status: path === '/healthz' ? 'ok' : 'ready' }),
      {
        headers: { 'content-type': 'application/json' },
      },
    );
  const file = path === '/' ? 'index.html' : path.slice(1);
  return new globalThis.Response(readFileSync(new URL(`../src/web/${file}`, import.meta.url)));
};
it('requires live health and exact source bytes from fixed public destinations', async () => {
  const request = vi.fn(fixture);
  expect(await checkRelease(request)).toBe(true);
  expect(request.mock.calls.map(([url]) => url)).toEqual([
    origin + '/healthz',
    origin + '/readyz',
    origin + '/',
    origin + '/portal.css',
    origin + '/portal.mjs',
    origin + '/operations.mjs',
  ]);
  for (const [, options] of request.mock.calls) {
    expect(options.credentials).toBe('omit');
    expect(options.redirect).toBe('error');
    expect(options.cache).toBe('no-store');
  }
});
it.each([
  () => new globalThis.Response('older release'),
  () => new globalThis.Response('private provider body', { status: 503 }),
  async () => {
    const r = await fixture(origin + '/');
    r.headers.set('age', '10');
    return r;
  },
  () => new globalThis.Response(new Uint8Array(1024 * 1024 + 1)),
  () => {
    throw new Error('private failure');
  },
])('refuses stale, unavailable, cached, oversized and failed assets', async (bad) => {
  expect(
    await checkRelease((url, options) => (url === origin + '/' ? bad() : fixture(url, options))),
  ).toBe(false);
});
it('does not hide failed persistence readiness behind matching UI', async () => {
  expect(
    await checkRelease((url) =>
      url.endsWith('/readyz') ? new globalThis.Response('{}', { status: 503 }) : fixture(url),
    ),
  ).toBe(false);
});
it('bounds a stalled asset transport', async () => {
  expect(
    await checkRelease((url) => (url === origin + '/' ? new Promise(() => {}) : fixture(url)), 10),
  ).toBe(false);
});
it('bounds stalled asset bodies and cancels the reader', async () => {
  const cancel = vi.fn();
  expect(
    await checkRelease(
      (url) =>
        url === origin + '/'
          ? new globalThis.Response(new globalThis.ReadableStream({ cancel }))
          : fixture(url),
      10,
    ),
  ).toBe(false);
  expect(cancel).toHaveBeenCalledOnce();
});
