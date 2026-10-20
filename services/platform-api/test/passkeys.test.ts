import { afterEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { SoftAuthenticator } from '../../../packages/auth/test/soft-authenticator.ts';
import { loadConfig } from '../src/config.ts';
import { makeEnv, PW, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

const rp = { rpId: 'localhost', origin: 'http://localhost:8080' };

async function setup(enabled = true) {
  env = await makeEnv({
    config: enabled ? { webauthn: { ...rp, rpName: 'Rokela Bai Bureh Warrior' } } : {},
  });
  const user = await env.register('passkey-user@example.test');
  const register = async (a: SoftAuthenticator, token = user.token, name = 'My phone') => {
    const begin = await env.call('POST', '/v1/auth/passkeys/register/begin', {
      token,
      body: { password: PW },
    });
    expect(begin.status).toBe(200);
    const cred = a.register(rp, begin.body.challenge);
    return env.call('POST', '/v1/auth/passkeys/register/finish', {
      token,
      body: { name, credential: { id: cred.id, type: cred.type, response: cred.response } },
    });
  };
  const loginWith = async (
    a: SoftAuthenticator,
    knobs: Parameters<SoftAuthenticator['assert']>[3] = {},
    challenge?: string,
  ) => {
    const ch =
      challenge ??
      (await env.call('POST', '/v1/auth/passkeys/login/begin', { body: {} })).body.challenge;
    const cred = a.assert(rp, ch, user.userId, knobs);
    const r = await env.call('POST', '/v1/auth/passkeys/login/finish', {
      body: { credential: { id: cred.id, type: cred.type, response: cred.response } },
    });
    return { ...r, challenge: ch };
  };
  return { user, register, loginWith };
}

const actions = async () => (await env.c.audit.list({ limit: 500 })).map((e) => e.action);

describe('passkeys', () => {
  it('are disabled (409) unless configured, and the options say so', async () => {
    const { user } = await setup(false);
    expect((await env.call('GET', '/v1/auth/options')).body.passkeys_configured).toBe(false);
    expect(
      (
        await env.call('POST', '/v1/auth/passkeys/register/begin', {
          token: user.token,
          body: { password: PW },
        })
      ).status,
    ).toBe(409);
    expect((await env.call('POST', '/v1/auth/passkeys/login/begin', { body: {} })).status).toBe(
      409,
    );
  });

  it('registers after password re-authentication and signs in without a password', async () => {
    const { user, register, loginWith } = await setup();
    expect((await env.call('GET', '/v1/auth/options')).body.passkeys_configured).toBe(true);
    const wrong = await env.call('POST', '/v1/auth/passkeys/register/begin', {
      token: user.token,
      body: { password: 'not the password' },
    });
    expect(wrong.status).toBe(401);
    const a = new SoftAuthenticator(-7);
    const reg = await register(a);
    expect(reg.status).toBe(201);
    expect(reg.body).toMatchObject({ id: a.id, name: 'My phone' });
    const list = await env.call('GET', '/v1/auth/passkeys', { token: user.token });
    expect(list.body.items).toHaveLength(1);
    expect(JSON.stringify(list.body)).not.toMatch(/"x"|"y"|jwk|public/i);
    const login = await loginWith(a);
    expect(login.status).toBe(200);
    const me = await env.call('GET', '/v1/auth/me', { token: login.body.token });
    expect(me.status).toBe(200);
    expect(me.body.id ?? me.body.user_id ?? me.body.user?.id).toBe(user.userId);
    expect(await actions()).toEqual(
      expect.arrayContaining(['identity.passkey_added', 'user.login_succeeded']),
    );
    const begin = await env.call('POST', '/v1/auth/passkeys/register/begin', {
      token: user.token,
      body: { password: PW },
    });
    expect(begin.body.excludeCredentials).toEqual([{ type: 'public-key', id: a.id }]);
    expect(begin.body.authenticatorSelection.userVerification).toBe('required');
  });

  it('uses each challenge once, for its purpose, and only before it expires', async () => {
    const { user, register, loginWith } = await setup();
    const a = new SoftAuthenticator(-8);
    await register(a);
    const first = await loginWith(a);
    expect(first.status).toBe(200);
    expect((await loginWith(a, {}, first.challenge)).status).toBe(401); // replayed challenge
    const ch = (await env.call('POST', '/v1/auth/passkeys/login/begin', { body: {} })).body
      .challenge;
    env.clock.advance(5 * 60_000);
    expect((await loginWith(a, {}, ch)).status).toBe(401); // expired
    // a registration challenge is not a sign-in challenge
    const regCh = (
      await env.call('POST', '/v1/auth/passkeys/register/begin', {
        token: user.token,
        body: { password: PW },
      })
    ).body.challenge;
    expect((await loginWith(a, {}, regCh)).status).toBe(401);
  });

  it('binds a registration challenge to the session that asked for it', async () => {
    const { user } = await setup();
    const other = await env.login('passkey-user@example.test');
    const begin = await env.call('POST', '/v1/auth/passkeys/register/begin', {
      token: user.token,
      body: { password: PW },
    });
    const a = new SoftAuthenticator(-7);
    const cred = a.register(rp, begin.body.challenge);
    const finish = await env.call('POST', '/v1/auth/passkeys/register/finish', {
      token: other,
      body: {
        name: 'Stolen',
        credential: { id: cred.id, type: cred.type, response: cred.response },
      },
    });
    expect(finish.status).toBe(400);
    expect((await env.call('GET', '/v1/auth/passkeys', { token: user.token })).body.items).toEqual(
      [],
    );
  });

  it('refuses forged, foreign-origin, unverified or mismatched assertions with one generic error', async () => {
    const { register, loginWith } = await setup();
    const a = new SoftAuthenticator(-7);
    await register(a);
    const stranger = new SoftAuthenticator(-7);
    const outcomes = [
      await loginWith(a, { badSignature: true }),
      await loginWith(a, { origin: 'https://evil.example' }),
      await loginWith(a, { rpId: 'evil.example' }),
      await loginWith(a, { flags: 0x01 }), // no user verification
      await loginWith(a, { userHandle: 'usr_somebody_else' }),
      await loginWith(stranger), // unknown credential
    ];
    for (const r of outcomes) {
      expect(r.status).toBe(401);
      expect(r.body.message).toBe('passkey sign-in failed');
    }
    expect((await loginWith(a)).status).toBe(200);
  });

  it('refuses a cloned authenticator (signature counter went backwards) and raises a signal', async () => {
    const { register, loginWith } = await setup();
    const a = new SoftAuthenticator(-7, { counter: 10 });
    await register(a);
    expect((await loginWith(a)).status).toBe(200); // 11
    expect((await loginWith(a)).status).toBe(200); // 12
    // Delivery is deliberately asynchronous, as it is with the PostgreSQL sink.
    const signal = env.c.telemetry.signal.bind(env.c.telemetry);
    env.c.telemetry.signal = async (...args) => {
      if (args[0] === 'passkey_counter_regression')
        await new Promise((resolve) => setTimeout(resolve, 50));
      return signal(...args);
    };
    const clone = await loginWith(a, { counter: 12 });
    expect(clone.status).toBe(401);
    await expect
      .poll(async () => (await env.signals()).map((s) => s.kind), { timeout: 5000 })
      .toContain('passkey_counter_regression');
    expect(await actions()).toContain('identity.passkey_counter_regression');
    expect((await loginWith(a)).status).toBe(200); // the genuine authenticator continues (13)
  });

  it('rejects registering a credential twice or for two accounts', async () => {
    const { register } = await setup();
    const a = new SoftAuthenticator(-7);
    expect((await register(a)).status).toBe(201);
    expect((await register(a)).status).toBe(409);
    const other = await env.register('second@example.test');
    expect((await register(a, other.token)).status).toBe(409);
  });

  it('removes a passkey only with the password and only the owner’s', async () => {
    const { user, register, loginWith } = await setup();
    const a = new SoftAuthenticator(-257);
    await register(a);
    const del = (token: string, password: string) =>
      env.call('POST', `/v1/auth/passkeys/${a.id}/delete`, { token, body: { password } });
    expect((await del(user.token, 'wrong password')).status).toBe(401);
    const other = await env.register('other@example.test');
    expect((await del(other.token, PW)).status).toBe(404);
    expect((await del(user.token, PW)).status).toBe(204);
    expect((await loginWith(a)).status).toBe(401);
    expect(await actions()).toContain('identity.passkey_removed');
  });
});

describe('passkey configuration', () => {
  const base = { NODE_ENV: 'test' } as NodeJS.ProcessEnv;
  it('needs both settings, a valid domain and an origin on it', () => {
    expect(loadConfig(base).webauthn).toBeUndefined();
    expect(() => loadConfig({ ...base, WEBAUTHN_RP_ID: 'rokela.example' })).toThrow(/both/);
    expect(() =>
      loadConfig({
        ...base,
        WEBAUTHN_RP_ID: 'rokela.example',
        WEBAUTHN_ORIGIN: 'https://evil.example',
      }),
    ).toThrow(/WEBAUTHN_ORIGIN/);
    expect(
      loadConfig({
        ...base,
        WEBAUTHN_RP_ID: 'rokela.example',
        WEBAUTHN_ORIGIN: 'https://app.rokela.example',
      }).webauthn,
    ).toEqual({
      rpId: 'rokela.example',
      origin: 'https://app.rokela.example',
      rpName: 'Rokela Bai Bureh Warrior',
    });
  });
  it('never puts random bytes in a challenge that is not 32 bytes of base64url', async () => {
    await setup();
    const { challenge } = (await env.call('POST', '/v1/auth/passkeys/login/begin', { body: {} }))
      .body;
    expect(Buffer.from(challenge, 'base64url')).toHaveLength(32);
    expect(challenge).not.toBe(randomBytes(32).toString('base64url'));
  });
});
