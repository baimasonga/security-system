import { afterEach, describe, expect, it } from 'vitest';
import { Writable } from 'node:stream';
import {
  MemorySecureStore,
  SoftwareDeviceKey,
  TrustPlatformClient,
  verifyLease,
} from '@trust/sdk-core';
import { DAY, PW, makeEnv, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

describe('HTTP basics and hardening', () => {
  it('serves health, sets security headers and a server-generated request id', async () => {
    env = await makeEnv();
    const r = await env.call('GET', '/healthz', { headers: { 'x-request-id': 'attacker-chosen' } });
    expect(r.status).toBe(200);
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['cache-control']).toBe('no-store');
    expect(String(r.headers['content-security-policy'])).toContain("default-src 'none'");
    expect(r.headers['x-request-id']).not.toBe('attacker-chosen');
  });

  it('unknown routes return a problem document without internals', async () => {
    env = await makeEnv();
    const r = await env.call('GET', '/v1/nope');
    expect(r.status).toBe(404);
    expect(r.body).toMatchObject({ code: 'not_found' });
    expect(JSON.stringify(r.body)).not.toMatch(/stack|node_modules|at /);
  });

  it('rejects unknown fields, bad types and oversize bodies without echoing values', async () => {
    env = await makeEnv();
    const extra = await env.call('POST', '/v1/auth/register', {
      body: { email: 'a@b.co', password: PW, is_admin: true },
    });
    expect(extra).toMatchObject({ status: 400, body: { code: 'invalid_request' } });
    const secret = 'S3cr3t-value-that-must-not-be-echoed';
    const bad = await env.call('POST', '/v1/auth/login', {
      body: { email: 12345, password: secret },
    });
    expect(bad.status).toBe(400);
    expect(JSON.stringify(bad.body)).not.toContain(secret);
    const big = await env.call('POST', '/v1/auth/login', {
      body: { email: 'a@b.co', password: 'x'.repeat(100_000) },
    });
    expect(big.status).toBe(413);
  });

  it('requires authentication on protected routes and rejects malformed bearer tokens', async () => {
    env = await makeEnv();
    for (const [m, u] of [
      ['GET', '/v1/organizations'],
      ['GET', '/v1/auth/me'],
      ['POST', '/v1/organizations'],
      ['POST', '/v1/licenses/activate'],
    ] as const) {
      expect((await env.call(m, u)).status).toBe(401);
    }
    expect(
      (await env.call('GET', '/v1/auth/me', { headers: { authorization: 'Bearer' } })).status,
    ).toBe(401);
    expect(
      (await env.call('GET', '/v1/auth/me', { headers: { authorization: 'Basic abc' } })).status,
    ).toBe(401);
    expect((await env.call('GET', '/v1/auth/me', { token: 'sess_' + 'a'.repeat(43) })).status).toBe(
      401,
    );
  });

  it('rate limits abusive login attempts', async () => {
    env = await makeEnv({
      config: {
        rateLimits: { global: 1000, login: 3, register: 100, challenge: 100, activate: 100 },
      },
    });
    const codes: number[] = [];
    for (let i = 0; i < 6; i++)
      codes.push(
        (
          await env.call('POST', '/v1/auth/login', {
            body: { email: 'a@b.co', password: 'wrong-wrong-wrong' },
          })
        ).status,
      );
    expect(codes.slice(0, 3)).toEqual([401, 401, 401]);
    expect(codes.slice(3).every((c) => c === 429)).toBe(true);
  });

  it('logs never contain bearer tokens, license keys, nonces or signatures', async () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(chunk, _e, cb) {
        lines.push(String(chunk));
        cb();
      },
    });
    env = await makeEnv({ app: { logger: true, logStream: stream } });
    const u = await env.register('a@b.co');
    const { licenseKey } = await env.provision(u.orgId);
    const dev = SoftwareDeviceKey.generate();
    const inst = 'inst_logtestlogtestlogtest';
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: inst },
    });
    const { buildProofMessage } = await import('@trust/crypto/verify');
    const sig = dev.sign(
      buildProofMessage({
        purpose: 'activate',
        nonce: ch.body.nonce,
        installationId: inst,
        subjectId: '',
        thumbprint: dev.thumbprint,
      }),
    );
    const act = await env.call('POST', '/v1/licenses/activate', {
      token: u.token,
      body: {
        license_key: licenseKey,
        installation_id: inst,
        device_public_key: dev.publicJwk,
        nonce: ch.body.nonce,
        signature: sig,
      },
    });
    expect(act.status).toBe(200);
    const all = lines.join('\n');
    expect(all.length).toBeGreaterThan(100);
    for (const secret of [u.token, licenseKey, ch.body.nonce, sig, act.body.lease])
      expect(all).not.toContain(secret);
    expect(all).not.toMatch(/"authorization"\s*:\s*"Bearer/);
  });

  it('unexpected failures return a generic 500 without leaking internals, and nothing is half-persisted', async () => {
    env = await makeEnv();
    const u = await env.register('a@b.co');
    const { licenseKey, licenseId } = await env.provision(u.orgId);
    env.c.keyring.revoke(env.c.keyring.activeKeyId('license'), 'drill');
    const dev = SoftwareDeviceKey.generate();
    const inst = 'inst_failclosedfailclosed1';
    const ch = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose: 'activate', installation_id: inst },
    });
    const { buildProofMessage } = await import('@trust/crypto/verify');
    const sig = dev.sign(
      buildProofMessage({
        purpose: 'activate',
        nonce: ch.body.nonce,
        installationId: inst,
        subjectId: '',
        thumbprint: dev.thumbprint,
      }),
    );
    const r = await env.call('POST', '/v1/licenses/activate', {
      token: u.token,
      body: {
        license_key: licenseKey,
        installation_id: inst,
        device_public_key: dev.publicJwk,
        nonce: ch.body.nonce,
        signature: sig,
      },
    });
    expect(r.status).toBe(500);
    expect(r.body).toMatchObject({ code: 'internal', message: 'lease signing unavailable' });
    const lic = await env.call('GET', `/v1/organizations/${u.orgId}/licenses/${licenseId}`, {
      token: u.token,
    });
    expect(lic.body.active_devices).toBe(0);
  });
});

describe('the vertical slice over HTTP', () => {
  it('product → plan → subscription → license → device → activation → lease → validation → refresh → deactivation', async () => {
    env = await makeEnv();
    const alice = await env.register('alice@example.test');
    const { licenseKey, licenseId, planId } = await env.provision(alice.orgId);

    // customer sees the license, its resolved entitlements and no secrets
    const list = await env.call('GET', `/v1/organizations/${alice.orgId}/licenses`, {
      token: alice.token,
    });
    expect(list.body.items).toHaveLength(1);
    expect(list.body.items[0]).toMatchObject({
      id: licenseId,
      status: 'valid',
      kind: 'subscription',
      product_code: 'pdf-pro',
      tier: 'professional',
      device_limit: 3,
      active_devices: 0,
    });
    expect(JSON.stringify(list.body)).not.toMatch(/key_digest|LK-/);
    const ent = await env.call(
      'GET',
      `/v1/entitlements?org_id=${alice.orgId}&license_id=${licenseId}`,
      { token: alice.token },
    );
    expect(ent.body).toMatchObject({
      status: 'valid',
      entitlements: { tier: 'professional', device_limit: 3 },
    });

    // a real SDK client activates against the real routes (in-process fetch bridge)
    const trust = (await env.call('GET', '/v1/keys/trust-bundle')).body;
    expect(JSON.stringify(trust)).not.toMatch(/"d"\s*:/);
    const fetchBridge: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const res = await env.app.inject({
        method: (init?.method ?? 'GET') as 'GET',
        url: url.pathname + url.search,
        headers: init?.headers as Record<string, string>,
        ...(init?.body ? { payload: init.body as string } : {}),
      });
      return new Response(res.body, { status: res.statusCode });
    };
    const client = new TrustPlatformClient({
      baseUrl: 'http://platform.test',
      productCode: 'pdf-pro',
      trust,
      store: new MemorySecureStore(),
      fetch: fetchBridge,
      now: env.clock.now,
    });

    const first = await client.activate(alice.token, licenseKey);
    expect(first.state).toBe('valid');
    expect(await client.getEntitlements()).toMatchObject({
      state: 'valid',
      capabilities: ['CLOUD_SYNC', 'OCR_ADVANCED'],
      tier: 'professional',
      planVersion: 1,
    });
    expect(await client.validateLicense()).toMatchObject({ status: 'valid' });

    // device appears in the customer's device list
    const acts = await env.call(
      'GET',
      `/v1/organizations/${alice.orgId}/licenses/${licenseId}/activations`,
      { token: alice.token },
    );
    expect(acts.body.items).toHaveLength(1);

    // operator changes the plan; the already-installed client picks it up on refresh, no release needed
    const op = await env.operatorToken();
    const patch = await env.call('PATCH', `/v1/admin/plans/${planId}`, {
      token: op,
      body: {
        capabilities: ['OCR_ADVANCED', 'CLOUD_SYNC', 'AI_DOCUMENT_ASSISTANT'],
        reason: 'launch AI add-on',
      },
    });
    expect(patch.body.version).toBe(2);
    env.clock.advance(16 * DAY);
    expect((await client.getEntitlements()).state).toBe('refresh_recommended');
    await client.refreshLease();
    const after = await client.getEntitlements();
    expect(after).toMatchObject({ state: 'valid', planVersion: 2 });
    expect(after.capabilities).toContain('AI_DOCUMENT_ASSISTANT');

    // owner deactivates the device remotely; the device's next online contact is refused
    const fresh = await env.login('alice@example.test'); // the 12h session from before the clock jump has (correctly) expired
    expect((await env.call('GET', '/v1/auth/me', { token: alice.token })).status).toBe(401);
    const deact = await env.call(
      'POST',
      `/v1/organizations/${alice.orgId}/activations/${acts.body.items[0].id}/deactivate`,
      { token: fresh },
    );
    expect(deact.status).toBe(200);
    await expect(client.refreshLease()).rejects.toMatchObject({ code: 'activation_not_found' });
  });

  it('SDK works offline until the lease expires, then degrades without destroying anything', async () => {
    env = await makeEnv();
    const alice = await env.register('alice@example.test');
    const { licenseKey } = await env.provision(alice.orgId);
    const trust = (await env.call('GET', '/v1/keys/trust-bundle')).body;
    let online = true;
    const bridge: typeof fetch = async (input, init) => {
      if (!online) throw new TypeError('network down');
      const url = new URL(String(input));
      const res = await env.app.inject({
        method: (init?.method ?? 'GET') as 'GET',
        url: url.pathname,
        headers: init?.headers as Record<string, string>,
        ...(init?.body ? { payload: init.body as string } : {}),
      });
      return new Response(res.body, { status: res.statusCode });
    };
    const store = new MemorySecureStore();
    const client = new TrustPlatformClient({
      baseUrl: 'http://platform.test',
      productCode: 'pdf-pro',
      trust,
      store,
      fetch: bridge,
      now: env.clock.now,
    });
    await client.activate(alice.token, licenseKey);

    online = false;
    env.clock.advance(20 * DAY); // past refresh_after, still inside the 30-day lease (and the sub period + grace)
    expect((await client.getEntitlements()).state).toBe('refresh_recommended');
    expect(await client.maintainLease()).toBeUndefined(); // offline: keeps working, does not throw
    expect((await client.getEntitlements()).capabilities).toContain('OCR_ADVANCED');

    env.clock.advance(20 * DAY);
    const dead = await client.getEntitlements();
    expect(dead.state).toBe('expired');
    expect(dead.capabilities).toEqual([]); // premium surfaces off...
    expect(dead.tier).toBe('professional'); // ...but the host still has context for a "renew/reconnect" screen
  });

  it('a lease file copied to another machine is useless there', async () => {
    env = await makeEnv();
    const alice = await env.register('alice@example.test');
    const { licenseKey } = await env.provision(alice.orgId);
    const trust = (await env.call('GET', '/v1/keys/trust-bundle')).body;
    const bridge: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const res = await env.app.inject({
        method: (init?.method ?? 'GET') as 'GET',
        url: url.pathname,
        headers: init?.headers as Record<string, string>,
        ...(init?.body ? { payload: init.body as string } : {}),
      });
      return new Response(res.body, { status: res.statusCode });
    };
    const storeA = new MemorySecureStore();
    const a = new TrustPlatformClient({
      baseUrl: 'http://platform.test',
      productCode: 'pdf-pro',
      trust,
      store: storeA,
      fetch: bridge,
      now: env.clock.now,
    });
    await a.activate(alice.token, licenseKey);
    const lease = (await storeA.get('lease'))!;

    // machine B: new device key + installation id, but has the stolen lease file
    const storeB = new MemorySecureStore();
    await storeB.set('lease', lease);
    const b = new TrustPlatformClient({
      baseUrl: 'http://platform.test',
      productCode: 'pdf-pro',
      trust,
      store: storeB,
      fetch: bridge,
      now: env.clock.now,
    });
    expect(await b.getEntitlements()).toMatchObject({ state: 'invalid', capabilities: [] });
    // and also wrong-product on machine A's own identity
    const devA = SoftwareDeviceKey.fromPem((await storeA.get('device_key'))!);
    const wrongProduct = verifyLease(lease, {
      trust,
      productCode: 'other',
      installationId: (await storeA.get('installation_id'))!,
      deviceThumbprint: devA.thumbprint,
      now: env.clock.now(),
    });
    expect(wrongProduct).toEqual({ state: 'invalid', reason: 'wrong_product' });
  });
});
