import { expect, it, vi } from 'vitest';
import { checkRokelaAvailability } from '../../../tools/check-rokela-availability.mjs';

const health = () =>
  new globalThis.Response('{"ok":true}', {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
const signin = () =>
  new globalThis.Response(
    '<!DOCTYPE html><html><head><title>Rokela PDF Pro</title></head><body></body></html>',
    {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    },
  );
const healthy = vi.fn(async (url) => (url.endsWith('/api/v1/health') ? health() : signin()));

it('checks the fixed public health and sign-in pages without authority or redirect following', async () => {
  const result = await checkRokelaAvailability(healthy);
  expect(result).toEqual([
    { check: 'health', outcome: 'passed' },
    { check: 'signin', outcome: 'passed' },
  ]);
  expect(healthy.mock.calls.map(([url]) => url)).toEqual([
    'https://www.rokelapdf.com/api/v1/health',
    'https://www.rokelapdf.com/signin',
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
  [
    'server error',
    () =>
      new globalThis.Response('{"ok":true}', {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }),
  ],
  [
    'database down',
    () =>
      new globalThis.Response('{"ok":false}', {
        status: 503,
        headers: { 'content-type': 'application/json' },
      }),
  ],
  [
    'not ok',
    () =>
      new globalThis.Response('{"ok":false}', { headers: { 'content-type': 'application/json' } }),
  ],
  [
    'extra fields',
    () =>
      new globalThis.Response('{"ok":true,"extra":"private"}', {
        headers: { 'content-type': 'application/json' },
      }),
  ],
  [
    'html instead of json',
    () => new globalThis.Response('<html>ok</html>', { headers: { 'content-type': 'text/html' } }),
  ],
  [
    'cached',
    () =>
      new globalThis.Response('{"ok":true}', {
        headers: { 'content-type': 'application/json', age: '30' },
      }),
  ],
  [
    'oversized',
    () =>
      new globalThis.Response('{"ok":true}' + ' '.repeat(1024), {
        headers: { 'content-type': 'application/json' },
      }),
  ],
  [
    'transport error',
    () => {
      throw new Error('private provider error');
    },
  ],
])('never turns a failed health response into a pass (%s)', async (_name, bad) => {
  const result = await checkRokelaAvailability(async (url) =>
    url.endsWith('/api/v1/health') ? bad() : signin(),
  );
  expect(result).toEqual([
    { check: 'health', outcome: 'failed' },
    { check: 'signin', outcome: 'passed' },
  ]);
  expect(JSON.stringify(result)).not.toContain('private');
});

it.each([
  // A redirect, including the self-redirect loop of 24 October 2026, is refused by redirect: 'error'.
  [
    'redirect loop',
    () => {
      throw new TypeError('fetch failed: unexpected redirect');
    },
  ],
  [
    'redirect response',
    () =>
      new globalThis.Response(null, {
        status: 307,
        headers: { location: 'https://www.rokelapdf.com/signin' },
      }),
  ],
  [
    'error page',
    () =>
      new globalThis.Response('<html><title>500: Internal Server Error</title></html>', {
        status: 500,
        headers: { 'content-type': 'text/html' },
      }),
  ],
  [
    'wrong page',
    () =>
      new globalThis.Response('<html><title>Not found</title></html>', {
        headers: { 'content-type': 'text/html' },
      }),
  ],
  [
    'json instead of html',
    () =>
      new globalThis.Response('{"title":"<title>Rokela PDF Pro</title>"}', {
        headers: { 'content-type': 'application/json' },
      }),
  ],
  [
    'oversized',
    () =>
      new globalThis.Response('<title>Rokela PDF Pro</title>' + ' '.repeat(256 * 1024), {
        headers: { 'content-type': 'text/html' },
      }),
  ],
])('never turns a broken sign-in page into a pass (%s)', async (_name, bad) => {
  const result = await checkRokelaAvailability(async (url) =>
    url.endsWith('/signin') ? bad() : health(),
  );
  expect(result).toEqual([
    { check: 'health', outcome: 'passed' },
    { check: 'signin', outcome: 'failed' },
  ]);
});

it('bounds a stalled transport even when it ignores abort', async () => {
  const result = await checkRokelaAvailability(() => new Promise(() => {}), 10);
  expect(result.every((r) => r.outcome === 'failed')).toBe(true);
});

it('bounds a body stream that never finishes and cancels its reader', async () => {
  const cancel = vi.fn();
  const result = await checkRokelaAvailability(
    async (url) =>
      new globalThis.Response(new globalThis.ReadableStream({ cancel }), {
        headers: { 'content-type': url.endsWith('/signin') ? 'text/html' : 'application/json' },
      }),
    10,
  );
  expect(result.every((r) => r.outcome === 'failed')).toBe(true);
  expect(cancel).toHaveBeenCalledTimes(2);
});
