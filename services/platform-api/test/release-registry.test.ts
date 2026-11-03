import { randomUUID } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { afterEach, expect, it, vi } from 'vitest';
import { KeyRing } from '@trust/crypto';
import { InMemoryAuditLog } from '@trust/audit';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
import { MemoryRegistryStore, ReleaseRegistryService } from '../src/release-registry.ts';

let env: Env;
afterEach(async () => env?.app.close());
function root(expires = 1_800_000_000) {
  const ring = new KeyRing();
  const key = ring.generate('license');
  const role = { threshold: 1, keys: [{ kid: key.kid, jwk: key.publicJwk }] };
  const releaseKey = ring.generate('license');
  const releaseRole = { threshold: 1, keys: [{ kid: releaseKey.kid, jwk: releaseKey.publicJwk }] };
  return {
    schema: 1 as const,
    version: 1,
    expires,
    root: role,
    release: releaseRole,
    artifact_origins: ['https://updates.example'],
  };
}
async function setup(enabled = true) {
  env = await makeEnv({ config: { updateCatalogEnabled: enabled } });
  const user = await env.register('updates@example.test');
  const { productId } = await env.provision(user.orgId);
  const token = await env.operatorToken();
  const path = `/v1/admin/products/${productId}/update-registry`;
  const call = (suffix: string, body: unknown) => env.call('POST', path + suffix, { token, body });
  return { user, productId, token, path, call };
}
const target = { platform: 'windows-x64', channel: 'stable', reason: 'Prepare signed release' };
it('is explicitly disabled by default; validates the configuration flag', async () => {
  expect(loadConfig({ NODE_ENV: 'test' }).updateCatalogEnabled).toBe(false);
  expect(() => loadConfig({ NODE_ENV: 'test', UPDATE_CATALOG_ENABLED: 'yes' })).toThrow(
    'UPDATE_CATALOG_ENABLED',
  );
  expect(
    loadConfig({ NODE_ENV: 'test', UPDATE_CATALOG_ENABLED: 'true' }).updateCatalogEnabled,
  ).toBe(true);
  const { call } = await setup(false);
  expect((await call('', { root: root(), reason: 'Initial root registration' })).status).toBe(404);
});
it('reports deployment availability only to operators without claiming installation status', async () => {
  const { token, user } = await setup(false);
  const path = '/v1/admin/update-catalog/status';
  expect((await env.call('GET', path)).status).toBe(401);
  expect((await env.call('GET', path, { token: user.token })).status).toBe(403);
  const status = await env.call('GET', path, { token });
  expect(status.body).toEqual({ enabled: false });
  expect(status.headers['cache-control']).toBe('no-store');
  expect((await env.call('GET', path + '?unknown=1', { token })).status).toBe(400);
});
it('requires an operator, strict fields and a reason; never replaces a registered root', async () => {
  const { call, path, user, token } = await setup();
  expect((await env.call('GET', path)).status).toBe(401);
  expect((await env.call('GET', path, { token: user.token })).status).toBe(403);
  expect(
    (
      await env.call('POST', path, {
        token: user.token,
        body: { root: root(), reason: 'Not an operator' },
      })
    ).status,
  ).toBe(403);
  expect((await call('', { root: root() })).status).toBe(400);
  expect((await call('', { root: root(), reason: 'Initial root', extra: true })).status).toBe(400);
  const r = root();
  expect((await call('', { root: r, reason: 'Initial root' })).status).toBe(201);
  expect((await call('', { root: root(), reason: 'Replace authority' })).status).toBe(409);
  const got = await env.call('GET', path, { token });
  expect(got.body.root).toEqual(r);
  expect(got.body.targets).toEqual([]);
  expect((await env.call('GET', path + '?extra=true', { token })).status).toBe(400);
});
it('rejects private keys, threshold mistakes, wrong initial versions and expired roots', async () => {
  const { call } = await setup();
  const privateRoot = root();
  Object.assign(privateRoot.root.keys[0]!.jwk, { d: 'never accept private material' });
  for (const r of [
    privateRoot,
    { ...root(), version: 2 },
    { ...root(), expires: 1 },
    { ...root(), release: { threshold: 2, keys: root().release.keys } },
    { ...root(), extra: true },
  ]) {
    expect((await call('', { root: r, reason: 'Initial root' })).status).toBe(400);
  }
  expect((await call('', { root: root(), reason: 'Initial root' })).status).toBe(201);
});
it('serializes concurrent unique reservations and makes exact retries idempotent', async () => {
  const { call, path, token } = await setup();
  expect((await call('', { root: root(), reason: 'Initial root' })).status).toBe(201);
  expect((await call('/targets', target)).status).toBe(201);
  expect((await call('/targets', target)).status).toBe(409);
  const batch = await Promise.all(
    Array.from({ length: 20 }, () =>
      call('/reservations', { ...target, request_id: randomUUID() }),
    ),
  );
  expect(batch.map((r) => r.status)).toEqual(Array(20).fill(200));
  expect(batch.map((r) => r.body.sequence).sort((a, b) => a - b)).toEqual(
    Array.from({ length: 20 }, (_, i) => i + 1),
  );
  const request = { ...target, request_id: randomUUID() };
  const duplicates = await Promise.all(
    Array.from({ length: 8 }, () => call('/reservations', request)),
  );
  expect(duplicates.every((r) => r.status === 200 && r.body.sequence === 21)).toBe(true);
  expect((await call('/reservations', { ...request, channel: 'beta' })).status).toBe(409);
  const got = await env.call('GET', path, { token });
  expect(got.body.targets[0].reserved_sequence).toBe(21);
  const events = await env.c.audit.list({ limit: 100 });
  expect(events.filter((e) => e.action === 'updates.sequence_reserved')).toHaveLength(21);
});
it('keeps products and targets independent; refuses expired roots but preserves receipt retries', async () => {
  const { call, token, path } = await setup();
  const expires = Math.floor(env.clock.now().getTime() / 1000) + 120;
  expect((await call('', { root: root(expires), reason: 'Initial root' })).status).toBe(201);
  await call('/targets', target);
  await call('/targets', { ...target, channel: 'beta' });
  const receipt = { ...target, request_id: randomUUID() };
  expect((await call('/reservations', receipt)).body.sequence).toBe(1);
  expect(
    (await call('/reservations', { ...target, channel: 'beta', request_id: randomUUID() })).body
      .sequence,
  ).toBe(1);
  expect(
    (await call('/reservations', { ...target, channel: 'missing', request_id: randomUUID() }))
      .status,
  ).toBe(404);
  const product = await env.call('POST', '/v1/admin/products', {
    token,
    body: { code: 'other-app', name: 'Another product', reason: 'Separate product' },
  });
  const other = `/v1/admin/products/${product.body.id}/update-registry`;
  expect((await env.call('GET', other, { token })).status).toBe(404);
  expect(
    (await env.call('POST', other, { token, body: { root: root(), reason: 'Initial root' } }))
      .status,
  ).toBe(201);
  expect((await env.call('POST', other + '/targets', { token, body: target })).status).toBe(201);
  expect(
    (await env.call('POST', other + '/reservations', { token, body: receipt })).body.sequence,
  ).toBe(1);
  env.clock.advance(120000);
  expect((await call('/reservations', receipt)).body.sequence).toBe(1);
  expect((await call('/reservations', { ...target, request_id: randomUUID() })).status).toBe(409);
  expect((await env.call('GET', path, { token })).status).toBe(200);
});
it('does not commit a reservation when the audit append fails; retries reuse no committed number', async () => {
  const clock = { now: () => new Date('2026-03-01T00:00:00Z') };
  const audit = new InMemoryAuditLog(clock);
  const store = new MemoryRegistryStore(audit);
  const service = new ReleaseRegistryService(store, clock, async () => ({
    code: 'test',
    status: 'active',
  }));
  await service.register('product', { root: root(), reason: 'Initial root' }, 'operator');
  await service.addTarget('product', target, 'operator');
  const spy = vi
    .spyOn(audit, 'appendMany')
    .mockRejectedValueOnce(new Error('synthetic audit failure'));
  const input = { ...target, request_id: randomUUID() };
  await expect(service.reserve('product', input, 'operator')).rejects.toThrow(
    'synthetic audit failure',
  );
  spy.mockRestore();
  expect((await service.read('product')).targets[0]!.reservedSequence).toBe(0);
  // A restarted coordinator shares the durable store, not a process-local counter.
  const restarted = new ReleaseRegistryService(store, clock, async () => ({
    code: 'test',
    status: 'active',
  }));
  expect((await restarted.reserve('product', input, 'operator')).sequence).toBe(1);
});

it('caps targets, rejects backwards clocks, preserves support history and respects platform freeze', async () => {
  const { call, token, path } = await setup();
  await call('', { root: root(), reason: 'Initial root' });
  for (let i = 0; i < 32; i++)
    expect((await call('/targets', { ...target, channel: `channel-${i}` })).status).toBe(201);
  expect((await call('/targets', target)).status).toBe(409);
  env.clock.advance(-1000);
  expect(
    (await call('/reservations', { ...target, channel: 'channel-0', request_id: randomUUID() }))
      .status,
  ).toBe(409);
  env.clock.advance(1000);
  expect(
    (
      await env.call('POST', '/v1/admin/freezes', {
        token,
        body: { scope: 'platform', reason: 'Release incident' },
      })
    ).status,
  ).toBe(201);
  expect(
    (await call('/reservations', { ...target, channel: 'channel-0', request_id: randomUUID() }))
      .status,
  ).toBe(423);
  expect((await env.call('GET', path, { token })).status).toBe(200);
});

it('does not reuse a sequence while a previous coordinator is waiting for audit commit', async () => {
  const clock = { now: () => new Date('2026-03-01T00:00:00Z') };
  const audit = new InMemoryAuditLog(clock);
  const store = new MemoryRegistryStore(audit);
  const make = () =>
    new ReleaseRegistryService(store, clock, async () => ({ code: 'test', status: 'active' }));
  await make().register('product', { root: root(), reason: 'Initial root' }, 'operator');
  await make().addTarget('product', target, 'operator');
  let entered!: () => void, release!: () => void;
  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const append = audit.appendMany.bind(audit);
  const spy = vi.spyOn(audit, 'appendMany').mockImplementationOnce(async (events) => {
    entered();
    await gate;
    return append(events);
  });
  const first = make().reserve('product', { ...target, request_id: randomUUID() }, 'operator');
  await waiting;
  const second = make().reserve('product', { ...target, request_id: randomUUID() }, 'operator');
  await setImmediate();
  release();
  try {
    expect((await Promise.all([first, second])).map((r) => r.sequence)).toEqual([1, 2]);
    expect((await make().read('product')).targets[0]!.reservedSequence).toBe(2);
  } finally {
    spy.mockRestore();
  }
});
