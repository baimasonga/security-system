import { afterEach, expect, it } from 'vitest';
import { MemoryMailDelivery } from '../src/integrations/mail.ts';
import { makeEnv, PW, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());
const token = (mail: MemoryMailDelivery) =>
  mail.messages.at(-1)!.text.match(/#(?:reset|verify)=(recover_[A-Za-z0-9_-]+)/)![1]!;
it('uses generic reset responses, throttles delivery, resets once and revokes sessions', async () => {
  const mail = new MemoryMailDelivery();
  env = await makeEnv({ identityDelivery: mail });
  const user = await env.register('recover@example.test');
  const known = await env.call('POST', '/v1/auth/password/request', {
    body: { email: 'recover@example.test' },
  });
  const absent = await env.call('POST', '/v1/auth/password/request', {
    body: { email: 'missing@example.test' },
  });
  expect(known.status).toBe(202);
  expect(absent.status).toBe(202);
  expect(known.body).toEqual(absent.body);
  await env.c.auth.flushIdentityMail();
  expect(mail.messages).toHaveLength(1);
  const secret = token(mail);
  await env.call('POST', '/v1/auth/password/request', { body: { email: 'recover@example.test' } });
  await env.c.auth.flushIdentityMail();
  expect(mail.messages).toHaveLength(1);
  const body = { token: secret, password: 'a new correct password' };
  expect((await env.call('POST', '/v1/auth/password/reset', { body })).status).toBe(204);
  expect((await env.call('GET', '/v1/auth/me', { token: user.token })).status).toBe(401);
  expect(
    (
      await env.call('POST', '/v1/auth/login', {
        body: { email: 'recover@example.test', password: PW },
      })
    ).status,
  ).toBe(401);
  expect(
    (
      await env.call('POST', '/v1/auth/login', {
        body: { email: 'recover@example.test', password: body.password },
      })
    ).status,
  ).toBe(200);
  expect((await env.call('POST', '/v1/auth/password/reset', { body })).status).toBe(400);
  expect(JSON.stringify(await env.c.audit.list({ limit: 100 }))).not.toContain(secret);
});
it('rejects expired or wrong-purpose tokens and records email verification once', async () => {
  const mail = new MemoryMailDelivery();
  env = await makeEnv({ identityDelivery: mail });
  const user = await env.register('verify@example.test');
  expect((await env.call('POST', '/v1/auth/email/request', { body: {} })).status).toBe(401);
  expect(
    (await env.call('POST', '/v1/auth/email/request', { token: user.token, body: {} })).status,
  ).toBe(202);
  await env.c.auth.flushIdentityMail();
  expect(
    (
      await env.call('POST', '/v1/auth/email/request', {
        token: user.token,
        body: { untrusted: true },
      })
    ).status,
  ).toBe(400);
  const verification = token(mail);
  expect(
    (
      await env.call('POST', '/v1/auth/password/reset', {
        body: { token: verification, password: 'another password okay' },
      })
    ).status,
  ).toBe(400);
  expect(
    (await env.call('POST', '/v1/auth/email/verify', { body: { token: verification } })).status,
  ).toBe(204);
  expect((await env.call('GET', '/v1/auth/me', { token: user.token })).body.email_verified).toBe(
    true,
  );
  expect(
    (await env.call('POST', '/v1/auth/email/verify', { body: { token: verification } })).status,
  ).toBe(400);
  await env.call('POST', '/v1/auth/password/request', { body: { email: 'verify@example.test' } });
  await env.c.auth.flushIdentityMail();
  const reset = token(mail);
  env.clock.advance(15 * 60000);
  expect(
    (
      await env.call('POST', '/v1/auth/password/reset', {
        body: { token: reset, password: 'another password okay' },
      })
    ).status,
  ).toBe(400);
});
it('does not accept concurrent use of one reset token', async () => {
  const mail = new MemoryMailDelivery();
  env = await makeEnv({ identityDelivery: mail });
  await env.register('race@example.test');
  await env.call('POST', '/v1/auth/password/request', { body: { email: 'race@example.test' } });
  await env.c.auth.flushIdentityMail();
  const secret = token(mail);
  const results = await Promise.all([
    env.call('POST', '/v1/auth/password/reset', {
      body: { token: secret, password: 'first new password' },
    }),
    env.call('POST', '/v1/auth/password/reset', {
      body: { token: secret, password: 'second new password' },
    }),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([204, 400]);
});
it('reports disabled recovery uniformly without leaking configuration or accounts', async () => {
  env = await makeEnv();
  expect((await env.call('GET', '/v1/auth/options')).body.email_recovery_configured).toBe(false);
  expect(
    (
      await env.call('POST', '/v1/auth/password/request', {
        body: { email: 'missing@example.test' },
      })
    ).status,
  ).toBe(409);
});
