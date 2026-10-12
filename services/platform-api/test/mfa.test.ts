import { afterEach, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { totpCode } from '../../../packages/auth/src/mfa.ts';
import { makeEnv, PW, type Env } from './harness.ts';
import { MemoryMailDelivery } from '../src/integrations/mail.ts';
let env: Env;
afterEach(async () => env?.app.close());
const decode = (key: string) => {
  const out: number[] = [];
  let value = 0,
    bits = 0;
  for (const char of key) {
    value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  return Buffer.from(out);
};
const key = randomBytes(32).toString('hex');
const setup = async (enforce = false, mail?: MemoryMailDelivery) => {
  env = await makeEnv({
    config: { mfaEncryptionKey: key, requireOperatorMfa: enforce },
    identityDelivery: mail,
  });
  const user = await env.register('mfa@example.test');
  const call = (path: string, body: unknown, token = user.token) =>
    env.call('POST', `/v1/auth/mfa/${path}`, { token, body });
  const begin = await call('begin', { password: PW });
  expect(begin.status).toBe(200);
  const secret = decode(begin.body.setup_key);
  const code = () => totpCode(secret, Math.floor(env.clock.now().getTime() / 30000));
  return { user, call, code, begin, secret };
};
it('requires password to enroll, confirms a first code, revokes sessions and never exposes stored secrets', async () => {
  const { user, call, code, begin } = await setup();
  expect(begin.body.setup_key).toMatch(/^[A-Z2-7]{32}$/);
  expect((await call('begin', { password: 'incorrect' })).status).toBe(401);
  expect((await call('confirm', { password: PW, code: 'abcdef' })).status).toBe(400);
  expect((await call('confirm', { password: PW, code: '000000' })).status).toBe(401);
  const confirmed = await call('confirm', { password: PW, code: code() });
  expect(confirmed.status).toBe(200);
  expect(confirmed.body.recovery_codes).toHaveLength(10);
  expect((await env.call('GET', '/v1/auth/me', { token: user.token })).status).toBe(401);
  const login = (code?: string) =>
    env.call('POST', '/v1/auth/login', {
      body: { email: 'mfa@example.test', password: PW, ...(code ? { code } : {}) },
    });
  expect((await login()).status).toBe(401);
  expect((await login(code())).status).toBe(401); // confirmation consumed that counter
  env.clock.advance(30000);
  const results = await Promise.all([login(code()), login(code())]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  const token = results.find((r) => r.status === 200)!.body.token;
  const me = (await env.call('GET', '/v1/auth/me', { token })).body;
  expect(me.mfa_enabled).toBe(true);
  expect(JSON.stringify(me)).not.toContain(begin.body.setup_key);
  expect((await call('begin', { password: PW }, token)).status).toBe(409);
  expect(JSON.stringify(await env.c.audit.list({ limit: 100 }))).not.toContain(
    begin.body.setup_key,
  );
});
it('recovery codes work once concurrently; disable requires both factors and revokes all sessions', async () => {
  const { call, code } = await setup();
  const result = await call('confirm', { password: PW, code: code() });
  const codes = result.body.recovery_codes;
  const login = (code: string) =>
    env.call('POST', '/v1/auth/login', { body: { email: 'mfa@example.test', password: PW, code } });
  const outcomes = await Promise.all([login(codes[0]), login(codes[0])]);
  expect(outcomes.map((r) => r.status).sort()).toEqual([200, 401]);
  const token = outcomes.find((r) => r.status === 200)!.body.token;
  expect((await call('disable', { password: PW, code: codes[1] }, token)).status).toBe(400); // mandatory reason
  expect(
    (await call('disable', { password: 'bad', code: codes[1], reason: 'Lost device' }, token))
      .status,
  ).toBe(401);
  expect(
    (await call('disable', { password: PW, code: codes[1], reason: 'Replacing device' }, token))
      .status,
  ).toBe(204);
  expect((await env.call('GET', '/v1/auth/me', { token })).status).toBe(401);
  expect(
    (
      await env.call('POST', '/v1/auth/login', {
        body: { email: 'mfa@example.test', password: PW },
      })
    ).status,
  ).toBe(200);
});
it('password recovery preserves enabled MFA; expired enrollment cannot be confirmed', async () => {
  const mail = new MemoryMailDelivery();
  const { call, code } = await setup(false, mail);
  env.clock.advance(10 * 60000);
  expect((await call('confirm', { password: PW, code: code() })).status).toBe(401);
  const begin = await call('begin', { password: PW });
  expect(begin.status).toBe(200);
  const user = { email: 'mfa@example.test' };
  const secret = decode(begin.body.setup_key);
  const otp = totpCode(secret, Math.floor(env.clock.now().getTime() / 30000));
  expect((await call('confirm', { password: PW, code: otp })).status).toBe(200);
  await env.call('POST', '/v1/auth/password/request', { body: { email: user.email } });
  await env.c.auth.flushIdentityMail();
  const token = mail.messages[0]!.text.match(/#reset=(recover_[\w-]+)/)![1]!;
  expect(
    (
      await env.call('POST', '/v1/auth/password/reset', {
        body: { token, password: 'new password for recovery' },
      })
    ).status,
  ).toBe(204);
  expect(
    (
      await env.call('POST', '/v1/auth/login', {
        body: { email: user.email, password: 'new password for recovery' },
      })
    ).status,
  ).toBe(401);
  env.clock.advance(30000);
  expect(
    (
      await env.call('POST', '/v1/auth/login', {
        body: {
          email: user.email,
          password: 'new password for recovery',
          code: totpCode(secret, Math.floor(env.clock.now().getTime() / 30000)),
        },
      })
    ).status,
  ).toBe(200);
});
it('operator enforcement allows account enrollment and denies administration until MFA is enabled', async () => {
  const { user, call, code } = await setup(true);
  await env.c.auth.bootstrapPlatformAdmin('mfa@example.test', 'Testing enforcement');
  expect((await env.call('GET', '/v1/admin/metrics', { token: user.token })).status).toBe(403);
  expect((await env.call('GET', '/v1/auth/me', { token: user.token })).status).toBe(200);
  const confirmed = await call('confirm', { password: PW, code: code() });
  const logged = await env.call('POST', '/v1/auth/login', {
    body: { email: 'mfa@example.test', password: PW, code: confirmed.body.recovery_codes[0] },
  });
  expect(logged.status).toBe(200);
  expect((await env.call('GET', '/v1/admin/metrics', { token: logged.body.token })).status).toBe(
    200,
  );
});
it('does not offer enrollment without a stable encryption key', async () => {
  env = await makeEnv();
  const user = await env.register('none@example.test');
  expect(
    (await env.call('POST', '/v1/auth/mfa/begin', { token: user.token, body: { password: PW } }))
      .status,
  ).toBe(409);
});
it('shares account lockout across factor attempts and prevents code reuse from bypassing it', async () => {
  const { call, code } = await setup();
  const confirmed = await call('confirm', { password: PW, code: code() });
  const login = (factor?: string) =>
    env.call('POST', '/v1/auth/login', {
      body: { email: 'mfa@example.test', password: PW, ...(factor ? { code: factor } : {}) },
    });
  for (let i = 0; i < 5; i++) expect((await login()).status).toBe(401);
  expect((await login(confirmed.body.recovery_codes[0])).status).toBe(401);
  env.clock.advance(15 * 60000);
  expect((await login(confirmed.body.recovery_codes[0])).status).toBe(200);
});
