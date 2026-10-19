import { describe, expect, it } from 'vitest';
import type { EventService, InventoryStore, CredentialScope } from '../src/index.ts';
export interface EventFixture {
  store: InventoryStore;
  scope: CredentialScope;
  componentId: string;
  token: string;
  events: EventService;
  now(): Date;
}
const sample = (f: EventFixture) => ({
  schema: 1,
  events: [
    {
      id: '00000000-0000-4000-8000-000000000001',
      component_id: f.componentId,
      occurred_at: f.now().toISOString(),
      type: 'component.heartbeat',
      attributes: { status: 'healthy' },
    },
  ],
});
export function eventIngestionContract(make: () => Promise<EventFixture>) {
  describe('committed ingestion contract', () => {
    it('withholds acknowledgements until commit and rolls back a failed commit boundary', async () => {
      const f = await make(),
        original = f.store.transaction.bind(f.store);
      let reached!: () => void, release!: () => void;
      const atCommit = new Promise<void>((resolve) => (reached = resolve));
      const gate = new Promise<void>((resolve) => (release = resolve));
      f.store.transaction = (org, fn) =>
        original(org, async (tx) => {
          await fn(tx);
          reached();
          await gate;
          throw new Error('commit boundary failed');
        });
      const outcome = f.events.ingest(f.token, sample(f)).then(
        () => ({ ok: true }),
        () => ({ ok: false }),
      );
      let settled = false;
      void outcome.then(() => {
        settled = true;
      });
      try {
        await atCommit;
        expect(settled).toBe(false);
        expect(await f.store.findEvent(f.scope, sample(f).events[0]!.id)).toBeUndefined();
      } finally {
        release();
      }
      expect(await outcome).toEqual({ ok: false });
      f.store.transaction = original;
      expect(await f.store.findEvent(f.scope, sample(f).events[0]!.id)).toBeUndefined();
      expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toBeUndefined();
      expect((await f.events.ingest(f.token, sample(f))).accepted[0]?.disposition).toBe('stored');
    });
    it('recovers an ambiguous commit through an identical duplicate receipt', async () => {
      const f = await make(),
        original = f.store.transaction.bind(f.store);
      f.store.transaction = async (org, fn) => {
        await original(org, fn);
        throw new Error('commit response lost');
      };
      await expect(f.events.ingest(f.token, sample(f))).rejects.toThrow('commit response lost');
      f.store.transaction = original;
      const retry = await f.events.ingest(f.token, sample(f));
      expect(retry.accepted[0]?.disposition).toBe('duplicate');
      expect((await f.store.getEventCounter(f.scope.orgId, 'storage:org'))?.count).toBe(1);
    });
    it('serializes contending duplicates and immediate revocation with actual event writes', async () => {
      const f = await make();
      const results = await Promise.all(
        Array.from({ length: 8 }, () => f.events.ingest(f.token, sample(f))),
      );
      expect(
        results.flatMap((r) => r.accepted).filter((r) => r.disposition === 'stored'),
      ).toHaveLength(1);
      expect(
        results.flatMap((r) => r.accepted).filter((r) => r.disposition === 'duplicate'),
      ).toHaveLength(7);
      expect((await f.store.getEventCounter(f.scope.orgId, 'storage:org'))?.count).toBe(1);
      await f.store.transaction(f.scope.orgId, async (tx) => {
        const row = await tx.findCredential(f.token.split('.')[1]!);
        await tx.updateCredential({ ...row!, revokedAt: f.now() });
      });
      await expect(f.events.ingest(f.token, sample(f))).rejects.toMatchObject({
        code: 'unauthenticated',
      });
    });
    it('commits only fixed request charges for authenticated client refusals', async () => {
      const f = await make();
      for (let i = 0; i < 60; i++)
        await expect(f.events.ingest(f.token, { schema: 2, events: [] })).rejects.toMatchObject({
          code: 'unprocessable',
        });
      expect(
        (await f.store.getEventCounter(f.scope.orgId, 'request:' + f.token.split('.')[1]))
          ?.requestTimes,
      ).toHaveLength(60);
      expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toBeUndefined();
      await expect(f.events.ingest(f.token, sample(f))).rejects.toMatchObject({
        code: 'rate_limited',
      });
    });
  });
}

export function eventRevokeRaceContract(make: () => Promise<EventFixture>) {
  it('orders an in-flight event commit before waiting revocation', async () => {
    const f = await make(),
      original = f.store.transaction.bind(f.store);
    let reached!: () => void, release!: () => void;
    const atBoundary = new Promise<void>((resolve) => (reached = resolve)),
      gate = new Promise<void>((resolve) => (release = resolve));
    f.store.transaction = (org, fn) =>
      original(org, async (tx) => {
        const result = await fn(tx);
        reached();
        await gate;
        return result;
      });
    const pending = f.events.ingest(f.token, sample(f));
    await atBoundary;
    let revoked = false;
    const revoke = original(f.scope.orgId, async (tx) => {
      const row = await tx.findCredential(f.token.split('.')[1]!);
      await tx.updateCredential({ ...row!, revokedAt: f.now() });
      revoked = true;
    });
    try {
      await Promise.resolve();
      expect(revoked).toBe(false);
    } finally {
      release();
    }
    const receipt = await pending;
    await revoke;
    f.store.transaction = original;
    expect(receipt.accepted[0]?.disposition).toBe('stored');
    expect(await f.store.findEvent(f.scope, sample(f).events[0]!.id)).toBeDefined();
    await expect(f.events.ingest(f.token, sample(f))).rejects.toMatchObject({
      code: 'unauthenticated',
    });
  });
}
