import { afterEach, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { totpCode } from '../../../packages/auth/src/mfa.ts';
import { makeEnv, PW, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
let env: Env;
afterEach(async () => env?.app.close());
const MFA_KEY = randomBytes(32).toString('hex');
function decode(value: string) {
  let bits = 0,
    n = 0;
  const out: number[] = [];
  for (const c of value) {
    n = (n << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((n >>> bits) & 255);
    }
  }
  return Buffer.from(out);
}
async function setup(logs?: string[]) {
  env = await makeEnv({
    config: {
      operationsIngestionEnabled: true,
      operationsInventoryEnabled: true,
      operationsCredentialsEnabled: true,
      mfaEncryptionKey: MFA_KEY,
    },
    ...(logs ? { app: { logger: true, logStream: { write: (s: string) => logs.push(s) } } } : {}),
  });
  const owner = await env.register('owner@example.test');
  const other = await env.register('other@example.test');
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const app = await env.call('POST', base, {
    token: owner.token,
    body: {
      code: 'rokela-pdf',
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  expect(app.status).toBe(201);
  const environment = await env.call('POST', base + '/' + app.body.id + '/environments', {
    token: owner.token,
    body: { code: 'staging', kind: 'staging', reason: 'initial_setup' },
  });
  expect(environment.status).toBe(201);
  const path = base + '/' + app.body.id + '/environments/' + environment.body.id + '/credentials';
  const component = await env.call(
    'POST',
    base + '/' + app.body.id + '/environments/' + environment.body.id + '/components',
    {
      token: owner.token,
      body: { code: 'converter', kind: 'worker', dependency_ids: [], reason: 'initial_setup' },
    },
  );
  expect(component.status).toBe(201);
  const scope = {
    orgId: owner.orgId,
    applicationId: app.body.id as string,
    environmentId: environment.body.id as string,
  };
  const begin = await env.call('POST', '/v1/auth/mfa/begin', {
    token: owner.token,
    body: { password: PW },
  });
  expect(begin.status).toBe(200);
  const secret = decode(begin.body.setup_key);
  const current = () => totpCode(secret, Math.floor(+env.clock.now() / 30000));
  const confirmed = await env.call('POST', '/v1/auth/mfa/confirm', {
    token: owner.token,
    body: { password: PW, code: current() },
  });
  expect(confirmed.status).toBe(200);
  env.clock.advance(30000);
  const login = await env.call('POST', '/v1/auth/login', {
    body: { email: 'owner@example.test', password: PW, code: current() },
  });
  expect(login.status).toBe(200);
  owner.token = login.body.token;
  const code = () => {
    env.clock.advance(30000);
    return current();
  };
  const call = (method: string, suffix = '', body?: unknown, token = owner.token) =>
    env.call(method, path + suffix, { token, ...(body ? { body } : {}) });
  const issue = (mfa = code()) =>
    call('POST', '', {
      purpose: 'events:write',
      ttl_seconds: 86400,
      reason: 'initial_setup',
      mfa_code: mfa,
    });
  return {
    componentId: component.body.id as string,
    owner,
    other,
    base,
    path,
    scope,
    code,
    call,
    issue,
    recovery: confirmed.body.recovery_codes as string[],
  };
}
const event = (componentId: string) => ({
  id: randomUUID(),
  component_id: componentId,
  occurred_at: env.clock.now().toISOString(),
  type: 'component.heartbeat',
  attributes: { status: 'healthy' },
});
it('commits safe receipts over the integration-only HTTP route and deduplicates retries', async () => {
  const f = await setup();
  const issued = await f.issue();
  expect(issued.status).toBe(201);
  const batch = { schema: 1, events: [event(f.componentId)] };
  const first = await env.call('POST', '/v1/operations/events', {
    token: issued.body.token,
    body: batch,
  });
  expect(first.status).toBe(200);
  expect(first.body.accepted[0]).toMatchObject({ id: batch.events[0]!.id, disposition: 'stored' });
  const retry = await env.call('POST', '/v1/operations/events', {
    token: issued.body.token,
    body: batch,
  });
  expect(retry.status).toBe(200);
  expect(retry.body.accepted[0]).toEqual({ ...first.body.accepted[0], disposition: 'duplicate' });
  expect(
    (await env.call('POST', '/v1/operations/events', { token: f.owner.token, body: batch })).status,
  ).toBe(401);
  expect(
    (await env.call('POST', '/v1/operations/events', { token: 'license-fixture', body: batch }))
      .status,
  ).toBe(401);
});
it('rejects source spoofing, private attributes, invalid batches and unsafe encodings without echoing names or values', async () => {
  const logs: string[] = [];
  const f = await setup(logs);
  const token = (await f.issue()).body.token;
  for (const body of [
    { schema: 1, org_id: f.owner.orgId, events: [event(f.componentId)] },
    {
      schema: 1,
      events: [
        {
          ...event(f.componentId),
          attributes: { status: 'healthy', 'private-file.pdf': 'person@example.test' },
        },
      ],
    },
    { schema: 2, events: [event(f.componentId)] },
    { schema: 1, events: Array.from({ length: 101 }, () => event(f.componentId)) },
  ]) {
    const r = await env.call('POST', '/v1/operations/events', { token, body });
    expect(r.status).toBe(422);
    expect(JSON.stringify(r.body)).not.toContain('private-file');
    expect(JSON.stringify(r.body)).not.toContain('person@example.test');
  }
  const encoded = await env.call('POST', '/v1/operations/events', {
    token,
    headers: { 'content-encoding': 'gzip' },
    body: { schema: 1, events: [event(f.componentId)] },
  });
  expect(encoded.status).toBe(415);
  const oversized = await env.app.inject({
    method: 'POST',
    url: '/v1/operations/events',
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    payload: JSON.stringify({ schema: 1, events: [], private: 'x'.repeat(262144) }),
  });
  expect(oversized.statusCode).toBe(413);
  expect(logs.join('')).not.toContain(token);
  expect(logs.join('')).not.toContain('private-file');
  expect(logs.join('')).not.toContain('person@example.test');
});
it('honors route enablement and immediate revocation, and bounds duplicate request rates with Retry-After', async () => {
  const f = await setup();
  const issued = (await f.issue()).body;
  const batch = { schema: 1, events: [event(f.componentId)] };
  env.c.config.operationsIngestionEnabled = false;
  expect(
    (await env.call('POST', '/v1/operations/events', { token: issued.token, body: batch })).status,
  ).toBe(404);
  env.c.config.operationsIngestionEnabled = true;
  for (let i = 0; i < 60; i++)
    expect(
      (await env.call('POST', '/v1/operations/events', { token: issued.token, body: batch }))
        .status,
    ).toBe(200);
  const limited = await env.call('POST', '/v1/operations/events', {
    token: issued.token,
    body: batch,
  });
  expect(limited.status).toBe(429);
  expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  const revoked = await f.call('POST', '/' + issued.credential.id + '/revoke', {
    reason: 'security_response',
    mfa_code: f.code(),
  });
  expect(revoked.status).toBe(200);
  expect(
    (await env.call('POST', '/v1/operations/events', { token: issued.token, body: batch })).status,
  ).toBe(401);
});
it('parses ingestion opt-in strictly and leaves it disabled by default', () => {
  expect(loadConfig({ NODE_ENV: 'test' }).operationsIngestionEnabled).toBe(false);
  expect(
    loadConfig({ NODE_ENV: 'test', OPERATIONS_INGESTION_ENABLED: 'true' })
      .operationsIngestionEnabled,
  ).toBe(true);
  expect(() => loadConfig({ NODE_ENV: 'test', OPERATIONS_INGESTION_ENABLED: 'yes' })).toThrow(
    'OPERATIONS_INGESTION_ENABLED',
  );
});

it('preserves ingestion during a management freeze', async () => {
  const f = await setup(),
    token = (await f.issue()).body.token;
  const operator = await env.c.auth.authenticate(await env.operatorToken());
  await env.c.privileged.freeze(operator.userId, f.owner.orgId, 'security_response');
  const result = await env.call('POST', '/v1/operations/events', {
    token,
    body: { schema: 1, events: [event(f.componentId)] },
  });
  expect(result.status).toBe(200);
});
it('maps a collector storage outage to a generic retryable response without leaking diagnostics', async () => {
  const logs: string[] = [];
  const f = await setup(logs),
    token = (await f.issue()).body.token;
  const original = env.c.operationsEvents.ingest;
  env.c.operationsEvents.ingest = async () => {
    throw new Error('private-file.pdf person@example.test');
  };
  try {
    const failed = await env.call('POST', '/v1/operations/events', {
      token,
      body: { schema: 1, events: [event(f.componentId)] },
    });
    expect(failed.status).toBe(503);
    expect(failed.body).toMatchObject({ code: 'unavailable', message: 'service unavailable' });
    expect(failed.headers['retry-after']).toBeUndefined();
    expect(JSON.stringify(failed.body)).not.toContain('private-file');
    expect(logs.join('')).not.toContain('private-file');
  } finally {
    env.c.operationsEvents.ingest = original;
  }
});
