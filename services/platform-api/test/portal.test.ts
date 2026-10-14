import { afterEach, expect, it } from 'vitest';
import { makeEnv, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());
it('serves an account-free portal with strict same-origin assets and preserves API CSP', async () => {
  env = await makeEnv();
  const page = await env.app.inject({ url: '/' });
  expect(page.statusCode).toBe(200);
  expect(page.headers['content-type']).toContain('text/html');
  expect(page.body).toContain('Rokela Bai Bureh Warrior');
  expect(page.body).toContain('href="/rokela-icon.png"');
  const icon = await env.app.inject({ url: '/rokela-icon.png' });
  expect(icon.statusCode).toBe(200);
  expect(icon.headers['content-type']).toBe('image/png');
  expect(icon.rawPayload.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  expect(page.body).not.toContain('sess_');
  expect(page.body).not.toMatch(/<script[^>]*>[^<]+<\/script>/);
  expect(page.headers['content-security-policy']).toContain("script-src 'self'");
  expect(page.headers['content-security-policy']).not.toContain('unsafe-inline');
  for (const url of ['/portal.mjs', '/portal.css', '/device.mjs'])
    expect((await env.app.inject({ url })).statusCode).toBe(200);
  expect((await env.app.inject({ url: '/v1/auth/me' })).statusCode).toBe(401);
  expect((await env.app.inject({ url: '/healthz' })).headers['content-security-policy']).toBe(
    "default-src 'none'; frame-ancestors 'none'",
  );
  expect((await env.app.inject({ url: '/web/../../config.ts' })).statusCode).toBe(404);
});
