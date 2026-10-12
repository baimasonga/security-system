import { afterEach, expect, it, vi } from 'vitest';
import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { createContainer } from '../src/container.ts';
let app: Awaited<ReturnType<typeof buildApp>>;
afterEach(async () => {
  await app?.close();
  vi.unstubAllGlobals();
});
it('configured Resend sends origin-bound recovery links; request Host cannot redirect them', async () => {
  let body: Record<string, unknown> | undefined;
  vi.stubGlobal('fetch', async (_url: unknown, options: RequestInit) => {
    body = JSON.parse(String(options.body));
    return new Response(JSON.stringify({ id: 'synthetic_email' }));
  });
  const config = loadConfig({
    NODE_ENV: 'test',
    RESEND_API_KEY: 'synthetic',
    EMAIL_FROM: 'trust@example.test',
    PUBLIC_ORIGIN: 'https://portal.example.test',
  });
  const c = await createContainer(config);
  app = await buildApp(c);
  await c.auth.register({
    email: 'recipient@example.test',
    password: 'correct horse battery staple',
  });
  const options = await app.inject({ url: '/v1/auth/options' });
  expect(options.json().email_recovery_configured).toBe(true);
  const response = await app.inject({
    method: 'POST',
    url: '/v1/auth/password/request',
    headers: { host: 'attacker.example' },
    payload: { email: 'recipient@example.test' },
  });
  expect(response.statusCode).toBe(202);
  await c.auth.flushIdentityMail();
  expect(String(body?.text)).toContain('https://portal.example.test/#reset=');
  expect(String(body?.text)).not.toContain('attacker.example');
});
it.each([
  'https://user:password@portal.example',
  'https://portal.example/path',
  'https://portal.example/?x=1',
  'not a url',
])('rejects unsafe configured origins without echoing them', (origin) => {
  expect(() =>
    loadConfig({
      NODE_ENV: 'test',
      RESEND_API_KEY: 'synthetic',
      EMAIL_FROM: 'trust@example.test',
      PUBLIC_ORIGIN: origin,
    }),
  ).toThrow(/PUBLIC_ORIGIN/);
  try {
    loadConfig({
      NODE_ENV: 'test',
      RESEND_API_KEY: 'synthetic',
      EMAIL_FROM: 'trust@example.test',
      PUBLIC_ORIGIN: origin,
    });
  } catch (e) {
    expect((e as Error).message).not.toContain(origin);
  }
});
