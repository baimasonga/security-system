import { describe, expect, it } from 'vitest';
import type { InventoryStore, CredentialScope, OperationEvent } from '../src/index.ts';
export function eventStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope; componentId: string }>,
) {
  describe('event store transaction contract', () => {
    it('persists scoped identity, rolls back counters/aggregates and bounds retention', async () => {
      const { store, scope, componentId } = await make();
      const now = new Date('2026-10-19T00:00:00Z');
      const event: OperationEvent = {
        ...scope,
        id: '00000000-0000-4000-8000-000000000001',
        componentId,
        credentialId: 'opc_' + 'a'.repeat(32),
        source: 'backend_report',
        type: 'component.heartbeat',
        attributes: { status: 'healthy' },
        occurredAt: now.toISOString(),
        receivedAt: now,
        expiresAt: new Date(+now + 30 * 86400000),
        contentHash: 'a'.repeat(64),
        sizeBytes: 600,
      };
      await expect(
        store.transaction(scope.orgId, async (tx) => {
          await tx.insertEvent(event);
          await tx.putEventCounter({
            orgId: scope.orgId,
            key: 'test',
            count: 1,
            bytes: 600,
            requestTimes: [],
            expiresAt: null,
          });
          await tx.addEventAggregate({
            ...scope,
            componentId,
            type: event.type,
            outcome: 'healthy',
            hour: now,
            count: 1,
            expiresAt: new Date(+now + 90 * 86400000),
          });
          throw new Error('rollback');
        }),
      ).rejects.toThrow('rollback');
      expect(await store.findEvent(scope, event.id)).toBeUndefined();
      expect(await store.getEventCounter(scope.orgId, 'test')).toBeUndefined();
      expect(
        await store.getEventAggregate(scope, componentId, event.type, now, 'healthy'),
      ).toBeUndefined();
      await store.transaction(scope.orgId, (tx) => tx.insertEvent(event));
      expect(await store.findEvent(scope, event.id)).toEqual(event);
      expect(
        await store.findEvent({ ...scope, environmentId: 'ope_' + 'f'.repeat(24) }, event.id),
      ).toBeUndefined();
      await expect(store.transaction(scope.orgId, (tx) => tx.insertEvent(event))).rejects.toThrow();
      expect(await store.expiredEventOrganizations(event.expiresAt, 25)).toContain(scope.orgId);
      await expect(
        store.transaction(scope.orgId, async (tx) => {
          await tx.pruneEventRows(scope.orgId, event.expiresAt, 1);
          await tx.putEventCounter({
            orgId: scope.orgId,
            key: 'test',
            count: 0,
            bytes: 0,
            requestTimes: [],
            expiresAt: null,
          });
          throw new Error('rollback retention');
        }),
      ).rejects.toThrow('rollback retention');
      expect(await store.findEvent(scope, event.id)).toEqual(event);
      expect(await store.getEventCounter(scope.orgId, 'test')).toBeUndefined();

      await store.transaction(scope.orgId, async (tx) => {
        expect(await tx.pruneEventRows(scope.orgId, now, 1)).toEqual([]);
        expect(await tx.pruneEventRows(scope.orgId, event.expiresAt, 1)).toEqual([event]);
      });
      expect(await store.findEvent(scope, event.id)).toBeUndefined();
    });
  });
}
