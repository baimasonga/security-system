import { expect, it } from 'vitest';
import { HealthService } from '../src/health.ts';
import { eventFixture } from './event-fixture.ts';
import { healthStoreContract } from './health-store-contract.ts';
const principal = {
  kind: 'user' as const,
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'test-session',
  platformRole: 'none' as const,
};
healthStoreContract(eventFixture);
it('does not revive stale health after clock rollback or service reconstruction', async () => {
  const f = await setup();
  await f.send('healthy');
  f.advance(180000);
  expect((await f.get()).components[0]?.status).toBe('stale');
  f.advance(-120000);
  const restarted = new HealthService({
    store: f.store,
    clock: { now: f.now },
    enabled: () => true,
    authorize: async () => {},
  });
  expect((await restarted.snapshot(principal, f.scope)).components[0]?.status).toBe('stale');
});
it('requires a new post-update observation after reactivating any inventory ancestor', async () => {
  for (const type of ['application', 'environment', 'component'] as const) {
    const f = await setup();
    await f.send('healthy');
    f.advance(1000);
    const id =
      type === 'application'
        ? f.scope.applicationId
        : type === 'environment'
          ? f.scope.environmentId
          : f.componentId;
    await f.store.transaction(f.scope.orgId, async (tx) => {
      const old = (await tx.find(type, f.scope.orgId, id))!;
      await tx.update(
        type,
        { ...old, state: 'disabled', version: old.version + 1, updatedAt: f.now() },
        old.version,
      );
      await tx.update(
        type,
        { ...old, state: 'active', version: old.version + 2, updatedAt: f.now() },
        old.version + 1,
      );
    });
    expect((await f.get()).components[0]?.status).toBe('unknown');
    await f.send('healthy');
    expect((await f.get()).components[0]?.status).toBe('unknown');
    f.advance(1);
    await f.send('healthy');
    expect((await f.get()).components[0]?.status).toBe('healthy');
  }
});
async function setup() {
  const f = await eventFixture();
  const key = await f.issue();
  let n = 0;
  const health = new HealthService({
    store: f.store,
    clock: { now: f.now },
    enabled: () => true,
    authorize: async () => {},
  });
  const send = (status: string, occurred = f.now()) =>
    f.events.ingest(key.token, {
      schema: 1,
      events: [
        {
          id: `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
          component_id: f.componentId,
          occurred_at: occurred.toISOString(),
          type: 'component.heartbeat',
          attributes: { status },
        },
      ],
    });
  return { ...f, health, send, get: () => health.snapshot(principal, f.scope) };
}
it('distinguishes missing, fresh, stale and recovery; queued older healthy cannot override failure', async () => {
  const f = await setup();
  expect((await f.get()).components[0]?.status).toBe('unknown');
  await f.send('unavailable');
  f.advance(60000);
  await f.send('healthy', new Date(+f.now() - 61000));
  expect((await f.get()).components[0]?.status).toBe('unavailable');
  f.advance(120000);
  expect((await f.get()).components[0]?.status).toBe('stale');
  await f.send('healthy');
  expect((await f.get()).components[0]?.status).toBe('healthy');
  f.advance(180000);
  expect((await f.get()).components[0]?.status).toBe('stale');
});
it('keeps delayed and future heartbeats as evidence without claiming health', async () => {
  const f = await setup();
  await expect(f.send('healthy', new Date(+f.now() - 120001))).resolves.toMatchObject({
    schema: 1,
  });
  expect((await f.get()).components[0]?.status).toBe('unknown');
  await expect(f.send('healthy', new Date(+f.now() + 1))).resolves.toMatchObject({ schema: 1 });
  expect((await f.get()).components[0]?.status).toBe('unknown');
  await f.send('healthy');
  expect((await f.get()).components[0]?.status).toBe('healthy');
  f.advance(1000);
  const result = await f.health.history(
    principal,
    f.scope,
    f.componentId,
    new Date(+f.now() - 3600000),
    f.now(),
  );
  expect(result.items.reduce((n, r) => n + r.count, 0)).toBe(3);
  expect(result.coverage).toBe('observations_only');
});
it('refuses disabled reads, unauthorized scopes and invalid history windows', async () => {
  const f = await setup();
  const disabled = new HealthService({
    store: f.store,
    clock: { now: f.now },
    enabled: () => false,
    authorize: async () => {},
  });
  await expect(disabled.snapshot(principal, f.scope)).rejects.toMatchObject({ code: 'not_found' });
  const denied = new HealthService({
    store: f.store,
    clock: { now: f.now },
    enabled: () => true,
    authorize: async () => {
      throw new Error('denied');
    },
  });
  await expect(denied.snapshot(principal, f.scope)).rejects.toThrow('denied');
  await expect(
    f.health.snapshot(principal, { ...f.scope, applicationId: 'opa_' + 'f'.repeat(24) }),
  ).rejects.toMatchObject({ code: 'not_found' });
  await expect(
    f.health.history(principal, f.scope, f.componentId, new Date(0), f.now()),
  ).rejects.toMatchObject({ code: 'invalid_request' });
});
it('propagates dependency failures without hiding missing own evidence, and inactive resources stay unknown', async () => {
  const f = await setup();
  const dependency = 'opm_' + 'b'.repeat(24);
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const c = (await tx.find('component', f.scope.orgId, f.componentId))!;
    await tx.insert('component', { ...c, id: dependency, code: 'storage', dependencyIds: [] });
    await tx.update('component', { ...c, dependencyIds: [dependency], version: 2 }, 1);
  });
  f.advance(1);
  await f.send('healthy');
  let snapshot = await f.get();
  expect(snapshot.components.find((r) => r.id === f.componentId)?.status).toBe('degraded');
  await f.store.transaction(f.scope.orgId, (tx) =>
    tx.recordHeartbeat({
      ...f.scope,
      componentId: dependency,
      status: 'unavailable',
      occurredAt: f.now(),
      receivedAt: f.now(),
      expiresAt: new Date(+f.now() + 86400000),
    }),
  );
  snapshot = await f.get();
  expect(snapshot.components.find((r) => r.id === f.componentId)?.status).toBe('unavailable');
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const c = (await tx.find('component', f.scope.orgId, f.componentId))!;
    await tx.update('component', { ...c, state: 'disabled', version: 3 }, 2);
  });
  expect((await f.get()).components.find((r) => r.id === f.componentId)?.status).toBe('unknown');
});
it('does not let same-occurrence healthy reports refresh receipt freshness', async () => {
  const f = await setup();
  const occurred = f.now();
  await f.send('healthy');
  f.advance(120000);
  await f.send('healthy', occurred);
  f.advance(60000);
  expect((await f.get()).components[0]?.status).toBe('stale');
});
it('bounds history independently by range, retained horizon and server time', async () => {
  const f = await setup(),
    now = f.now();
  await expect(
    f.health.history(principal, f.scope, f.componentId, new Date(+now - 86400001), now),
  ).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(
    f.health.history(
      principal,
      f.scope,
      f.componentId,
      new Date(+now - 91 * 86400000),
      new Date(+now - 91 * 86400000 + 3600000),
    ),
  ).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(
    f.health.history(principal, f.scope, f.componentId, now, new Date(+now + 1)),
  ).rejects.toMatchObject({ code: 'invalid_request' });
});
it('retains historical assertions after raw expiry without treating them as current health', async () => {
  const f = await setup(),
    occurred = f.now();
  await f.send('healthy');
  f.advance(31 * 86400000);
  await f.events.retain();
  expect((await f.get()).components[0]?.status).toBe('unknown');
  const result = await f.health.history(
    principal,
    f.scope,
    f.componentId,
    occurred,
    new Date(+occurred + 3600000),
  );
  expect(result.items.reduce((n, r) => n + r.count, 0)).toBe(1);
});
