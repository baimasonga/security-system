import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { MemorySecureStore, PlatformError, TrustPlatformClient } from '@trust/sdk-core';
import { makeEnv, DAY, PW, type Env } from '../../services/platform-api/test/harness.ts';

/** Real TCP socket + the platform's global fetch: proves the wire contract, not just inject(). */
describe('vertical slice over a real network socket', () => {
  let env: Env;
  let app: FastifyInstance;
  let base: string;

  beforeAll(async () => {
    env = await makeEnv();
    app = env.app;
    await app.listen({ host: '127.0.0.1', port: 0 });
    const addr = app.server.address();
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
  });
  afterAll(async () => app.close());

  const http = async (method: string, path: string, body?: unknown, token?: string) => {
    const r = await fetch(base + path, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? null : JSON.stringify(body),
    });
    const t = await r.text();
    return { status: r.status, body: t ? JSON.parse(t) : undefined };
  };

  it('activate → offline use → refresh → revoke → refusal, with the SDK talking HTTP', async () => {
    const reg = await http('POST', '/v1/auth/register', {
      email: 'net@example.test',
      password: PW,
    });
    expect(reg.status).toBe(201);
    const token = (
      await http('POST', '/v1/auth/login', { email: 'net@example.test', password: PW })
    ).body.token as string;
    const { licenseKey, licenseId } = await env.provision(reg.body.personal_org.id);
    const trust = (await http('GET', '/v1/keys/trust-bundle')).body;

    const client = new TrustPlatformClient({
      baseUrl: base,
      productCode: 'pdf-pro',
      trust,
      store: new MemorySecureStore(),
      now: env.clock.now,
    });
    expect((await client.activate(token, licenseKey)).state).toBe('valid');
    expect((await client.getEntitlements()).capabilities).toContain('OCR_ADVANCED');

    env.clock.advance(16 * DAY);
    expect((await client.refreshLease()).state).toBe('valid');

    // operator revokes → the very next online contact is refused with a definitive code
    const op = await env.login('operator@example.test'); // the earlier 12h operator session expired with the clock jump
    const rev = await http(
      'POST',
      `/v1/admin/organizations/${reg.body.personal_org.id}/licenses/${licenseId}/revoke`,
      { reason: 'fraud review #77' },
      op,
    );
    expect(rev.status).toBe(200);
    await expect(client.refreshLease()).rejects.toMatchObject({ code: 'activation_not_found' });
    await expect(client.validateLicense()).rejects.toBeInstanceOf(PlatformError);
    // a still-valid lease needs no network call...
    expect(await client.maintainLease()).toBeUndefined();
    // ...but once a refresh is due, definitive refusals (4xx) are surfaced instead of swallowed
    env.clock.advance(16 * DAY);
    await expect(client.maintainLease()).rejects.toMatchObject({ status: 404 });
  });

  it('surfaces stable problem codes to clients', async () => {
    const r = await http('POST', '/v1/auth/login', {
      email: 'nobody@example.test',
      password: 'whatever-whatever',
    });
    expect(r).toMatchObject({
      status: 401,
      body: { code: 'unauthenticated', message: 'invalid email or password' },
    });
    expect(r.body.request_id).toMatch(/^[0-9a-f-]{36}$/);
  });
});
