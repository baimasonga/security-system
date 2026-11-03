import { randomUUID } from 'node:crypto';
import { afterEach, expect, it } from 'vitest';
import { KeyRing, signJws } from '@trust/crypto';
import { SecureUpdateClient, type UpdateManifest } from '@trust/sdk-core';
import { makeEnv, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());
const target = { platform: 'windows-x64', channel: 'stable', reason: 'Publish trusted build' };
async function setup(enabled = true) {
  env = await makeEnv({ config: { updateCatalogEnabled: enabled } });
  const user = await env.register('publisher@example.test');
  const { productId } = await env.provision(user.orgId);
  const token = await env.operatorToken();
  const path = `/v1/admin/products/${productId}/update-registry`;
  const call = (suffix: string, body: unknown) => env.call('POST', path + suffix, { token, body });
  const ring = new KeyRing();
  const a = ring.generate('license'),
    b = ring.generate('license');
  ring.activate(b.kid);
  const now = Math.floor(env.clock.now().getTime() / 1000);
  const root = {
    schema: 1 as const,
    version: 1,
    expires: now + 3600,
    root: { threshold: 1, keys: [{ kid: a.kid, jwk: a.publicJwk }] },
    release: { threshold: 1, keys: [{ kid: b.kid, jwk: b.publicJwk }] },
    artifact_origins: ['https://updates.example'],
  };
  if (enabled) {
    expect((await call('', { root, reason: 'Register public authority' })).status).toBe(201);
    expect((await call('/targets', target)).status).toBe(201);
  }
  const reserve = async () => {
    const request_id = randomUUID();
    const r = await call('/reservations', { ...target, request_id });
    expect(r.status).toBe(200);
    return { request_id, sequence: r.body.sequence as number };
  };
  const sign = async (sequence: number, changes: Partial<UpdateManifest> = {}) => {
    const manifest: UpdateManifest = {
      schema: 1,
      product: (await env.c.updateRegistry.read(productId)).product,
      platform: target.platform,
      channel: target.channel,
      sequence,
      version: '1.0',
      minimum_sequence: 0,
      issued_at: now,
      expires: now + 300,
      paused: false,
      artifact: {
        url: 'https://updates.example/setup.exe',
        size: 10,
        sha256: 'a'.repeat(64),
        sbom_sha256: 'b'.repeat(64),
        provenance_sha256: 'c'.repeat(64),
      },
      ...changes,
    };
    return {
      signatures: [
        await signJws(
          { ...manifest },
          { kid: b.kid, typ: 'trust-update-manifest+jws' },
          ring.custody,
        ),
      ],
    };
  };
  const current = () =>
    env.call('GET', `/v1/updates/${productId}/current?platform=windows-x64&channel=stable`);
  return { productId, user, token, path, call, reserve, sign, current, root };
}
it('publishes a reserved signed envelope, serves exact SDK-compatible data and retains bounded private history', async () => {
  const f = await setup();
  expect((await f.current()).status).toBe(404);
  const r = await f.reserve();
  const envelope = await f.sign(r.sequence);
  const body = { ...target, request_id: r.request_id, envelope };
  expect((await f.call('/releases', body)).status).toBe(200);
  expect((await f.call('/releases', body)).status).toBe(200);
  const feed = await f.current();
  expect(feed.status).toBe(200);
  expect(feed.body).toEqual(envelope);
  expect(feed.headers['cache-control']).toBe('no-store');
  const sdk = new SecureUpdateClient({
    root: f.root,
    product: (await env.c.updateRegistry.read(f.productId)).product,
    platform: target.platform,
    channel: target.channel,
    now: () => env.clock.now(),
    store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
  });
  expect((await sdk.verifyManifest(feed.body)).sequence).toBe(1);
  const history = `${f.path}/releases?platform=windows-x64&channel=stable&limit=1`;
  expect((await env.call('GET', history, { token: f.token })).body.items).toHaveLength(1);
  expect((await env.call('GET', history)).status).toBe(401);
  expect((await env.call('GET', history, { token: f.user.token })).status).toBe(403);
  expect(
    (await env.call('GET', history.replace('limit=1', 'limit=51'), { token: f.token })).status,
  ).toBe(400);
  const events = await env.c.audit.list({ limit: 100 });
  expect(events.filter((e) => e.action === 'updates.release_published')).toHaveLength(1);
});
it('requires operator authorization, an enabled catalog, strict fields and a reservation', async () => {
  const f = await setup();
  const envelope = await f.sign(1);
  const body = { ...target, request_id: randomUUID(), envelope };
  expect((await env.call('POST', f.path + '/releases', { body })).status).toBe(401);
  expect((await env.call('POST', f.path + '/releases', { body, token: f.user.token })).status).toBe(
    403,
  );
  expect((await f.call('/releases', body)).status).toBe(404);
  expect((await f.call('/releases', { ...body, reason: '' })).status).toBe(400);
  expect((await f.call('/releases', { ...body, unknown: true })).status).toBe(400);
  expect(
    (
      await env.call(
        'GET',
        `/v1/updates/${f.productId}/current?platform=windows-x64&channel=stable&unknown=true`,
      )
    ).status,
  ).toBe(400);
  await env.app.close();
  const disabled = await setup(false);
  expect((await disabled.current()).status).toBe(404);
  expect((await disabled.call('/releases', body)).status).toBe(404);
});
it('rejects invalid signatures, wrong product/target/sequence, stale metadata and disallowed artifacts', async () => {
  const f = await setup();
  const r = await f.reserve();
  for (const change of [
    { product: 'another-product' },
    { channel: 'beta' },
    { platform: 'linux-x64' },
    { expires: 1 },
    { sequence: 99 },
    { issued_at: 1_999_999_999 },
    {
      artifact: {
        url: 'https://evil.example/setup',
        size: 1,
        sha256: 'a'.repeat(64),
        sbom_sha256: 'b'.repeat(64),
        provenance_sha256: 'c'.repeat(64),
      },
    },
  ]) {
    const result = await f.call('/releases', {
      ...target,
      request_id: r.request_id,
      envelope: await f.sign(1, change),
    });
    expect([400, 409]).toContain(result.status);
  }
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: r.request_id,
        envelope: { signatures: ['invalid'] },
      })
    ).status,
  ).toBe(400);
  expect((await f.current()).status).toBe(404);
});
it('prevents rollback and equivocation; signed pause replaces the feed and expiry never falls back', async () => {
  const f = await setup();
  const a = await f.reserve(),
    one = await f.sign(a.sequence);
  const first = { ...target, request_id: a.request_id, envelope: one };
  expect((await f.call('/releases', first)).status).toBe(200);
  const b = await f.reserve();
  const paused = await f.sign(b.sequence, {
    paused: true,
    expires: Math.floor(env.clock.now().getTime() / 1000) + 30,
  });
  expect(
    (await f.call('/releases', { ...target, request_id: b.request_id, envelope: paused })).status,
  ).toBe(200);
  expect((await f.call('/releases', first)).status).toBe(200);
  expect((await f.current()).body).toEqual(paused);
  expect(
    (
      await f.call('/releases', {
        ...first,
        envelope: await f.sign(a.sequence, { version: 'changed' }),
      })
    ).status,
  ).toBe(409);
  env.clock.advance(31_000);
  expect((await f.current()).status).toBe(404);
  expect(
    (await f.call('/releases', { ...target, request_id: b.request_id, envelope: paused })).status,
  ).toBe(200);
  const history = await env.call(
    'GET',
    f.path + '/releases?platform=windows-x64&channel=stable&before=2',
    { token: f.token },
  );
  expect(history.body.items.map((r: { sequence: number }) => r.sequence)).toEqual([1]);
});
it('reconciles historical floors without reusing sequences or allowing stale reservations to publish', async () => {
  const f = await setup();
  const old = await f.reserve();
  expect((await f.call('/sequence-floor', { ...target, sequence: 40 })).status).toBe(200);
  expect((await f.call('/sequence-floor', { ...target, sequence: 39 })).status).toBe(409);
  expect((await f.call('/sequence-floor', { ...target, sequence: 40 })).status).toBe(409);
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: old.request_id,
        envelope: await f.sign(old.sequence),
      })
    ).status,
  ).toBe(409);
  const next = await f.reserve();
  expect(next.sequence).toBe(41);
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: next.request_id,
        envelope: await f.sign(next.sequence),
      })
    ).status,
  ).toBe(200);
  expect((await f.call('/sequence-floor', { ...target, sequence: 99 })).status).toBe(409);
});
it('commits a single immutable publication across independent coordinators and concurrent exact retries', async () => {
  const f = await setup();
  const r = await f.reserve();
  const input = { ...target, request_id: r.request_id, envelope: await f.sign(r.sequence) };
  const registry = env.c.updateRegistry;
  const { ReleaseRegistryService } = await import('../src/release-registry.ts');
  const other = new ReleaseRegistryService(registry.store, env.clock, registry.product);
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      (i % 2 ? registry : other).publish(f.productId, input, 'operator'),
    ),
  );
  expect(results.every((row) => row.sequence === 1)).toBe(true);
  const history = await other.history(f.productId, {
    platform: target.platform,
    channel: target.channel,
    limit: 50,
  });
  expect(history).toHaveLength(1);
  expect(
    (await env.c.audit.list({ limit: 100 })).filter(
      (e) => e.action === 'updates.release_published',
    ),
  ).toHaveLength(1);
  input.envelope.signatures[0] = 'caller mutation';
  expect((await f.current()).body).toEqual(history[0]!.envelope);
});
it('rolls history and the registry clock back when audit append fails', async () => {
  const f = await setup();
  const r = await f.reserve();
  const input = { ...target, request_id: r.request_id, envelope: await f.sign(r.sequence) };
  const registry = env.c.updateRegistry;
  const { ReleaseRegistryService } = await import('../src/release-registry.ts');
  const failing = new ReleaseRegistryService(
    {
      read: (id) => registry.store.read(id),
      transaction: (id, work) =>
        registry.store.transaction(id, (tx) =>
          work({
            ...tx,
            audit: async () => {
              throw new Error('synthetic publication audit failure');
            },
          }),
        ),
    },
    env.clock,
    registry.product,
  );
  const before = await registry.read(f.productId);
  await expect(failing.publish(f.productId, input, 'operator')).rejects.toThrow(
    'synthetic publication audit failure',
  );
  expect((await f.current()).status).toBe(404);
  expect((await registry.read(f.productId)).updatedAt).toEqual(before.updatedAt);
  expect((await f.call('/releases', input)).status).toBe(200);
});
it('keeps target publications and product reservations isolated; refuses backwards clocks', async () => {
  const f = await setup();
  const r = await f.reserve();
  expect(
    (
      await f.call('/releases', {
        ...target,
        channel: 'beta',
        request_id: r.request_id,
        envelope: await f.sign(r.sequence),
      })
    ).status,
  ).toBe(409);
  const created = await env.call('POST', '/v1/admin/products', {
    token: f.token,
    body: { code: 'other-product', name: 'Other product', reason: 'Isolation test' },
  });
  expect(created.status).toBe(201);
  const other = { productId: created.body.id as string };
  expect(
    (
      await env.call('POST', `/v1/admin/products/${other.productId}/update-registry/releases`, {
        token: f.token,
        body: { ...target, request_id: r.request_id, envelope: await f.sign(r.sequence) },
      })
    ).status,
  ).toBe(404);
  env.clock.advance(-1_000);
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: r.request_id,
        envelope: await f.sign(r.sequence),
      })
    ).status,
  ).toBe(409);
});
it('blocks publication and floor mutation during platform freeze without hiding an existing signed feed', async () => {
  const f = await setup();
  const a = await f.reserve();
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: a.request_id,
        envelope: await f.sign(a.sequence),
      })
    ).status,
  ).toBe(200);
  const b = await f.reserve();
  expect(
    (
      await env.call('POST', '/v1/admin/freezes', {
        token: f.token,
        body: { scope: 'platform', reason: 'Release incident' },
      })
    ).status,
  ).toBe(201);
  expect(
    (
      await f.call('/releases', {
        ...target,
        request_id: b.request_id,
        envelope: await f.sign(b.sequence),
      })
    ).status,
  ).toBe(423);
  expect((await f.call('/sequence-floor', { ...target, sequence: 100 })).status).toBe(423);
  expect((await f.current()).status).toBe(200);
  env.clock.advance(3_601_000);
  expect((await f.current()).status).toBe(404);
});
