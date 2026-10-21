import { expect, it, vi } from 'vitest';
import { checkAvailability } from '../../../tools/check-warrior-availability.mjs';

const response = (status) =>
  new globalThis.Response(JSON.stringify({ status }), {
    headers: { 'content-type': 'application/json' },
  });
const healthy = vi.fn(async (url) => response(url.endsWith('/healthz') ? 'ok' : 'ready'));
it('checks fixed liveness and readiness independently without authority or redirect following', async () => {
  const result = await checkAvailability(healthy);
  expect(result).toEqual([
    { check: 'liveness', outcome: 'passed' },
    { check: 'readiness', outcome: 'passed' },
  ]);
  expect(healthy.mock.calls.map(([url]) => url)).toEqual([
    'https://trustplatform-api-production.up.railway.app/healthz',
    'https://trustplatform-api-production.up.railway.app/readyz',
  ]);
  for (const call of healthy.mock.calls) {
    const options = call[1];
    expect(options.redirect).toBe('error');
    expect(options.credentials).toBe('omit');
    expect(options.cache).toBe('no-store');
    expect(Object.keys(options.headers)).toEqual(['Accept', 'Cache-Control']);
    expect(options.signal?.aborted).toBe(true);
  }
});
it.each([
  () =>
    new globalThis.Response('{"status":"ready"}', {
      status: 503,
      headers: { 'content-type': 'application/json' },
    }),
  () => new globalThis.Response('<html>ready</html>', { headers: { 'content-type': 'text/html' } }),
  () => response('unavailable'),
  () =>
    new globalThis.Response('{"status":"ready","extra":"private"}', {
      headers: { 'content-type': 'application/json' },
    }),
  () =>
    new globalThis.Response('{"status":"ready"}', {
      headers: { 'content-type': 'application/json', age: '30' },
    }),
  () =>
    new globalThis.Response('{"status":"ready"}' + ' '.repeat(1024), {
      headers: { 'content-type': 'application/json' },
    }),
  () => {
    throw new Error('private provider error');
  },
])('never turns failed, invalid, cached or oversized readiness into a pass', async (bad) => {
  const result = await checkAvailability(async (url) =>
    url.endsWith('/healthz') ? response('ok') : bad(),
  );
  expect(result[0].outcome).toBe('passed');
  expect(result[1]).toEqual({ check: 'readiness', outcome: 'failed' });
  expect(JSON.stringify(result)).not.toContain('private');
});
it('bounds a stalled transport even when it ignores abort', async () => {
  const result = await checkAvailability(() => new Promise(() => {}), 10);
  expect(result.every((r) => r.outcome === 'failed')).toBe(true);
});
it('bounds a body stream that never finishes and cancels its reader', async () => {
  const cancel = vi.fn();
  const result = await checkAvailability(
    async () =>
      new globalThis.Response(new globalThis.ReadableStream({ cancel }), {
        headers: { 'content-type': 'application/json' },
      }),
    10,
  );
  expect(result.every((r) => r.outcome === 'failed')).toBe(true);
  expect(cancel).toHaveBeenCalledTimes(2);
});
