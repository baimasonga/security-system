import { expect, it } from 'vitest';
import type { CredentialScope, InventoryStore } from '../src/model.ts';
import type { Heartbeat } from '../src/health.ts';
export function healthStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope; componentId: string }>,
) {
  it('persists occurrence ordering, conservative ties, scope and transactional rollback', async () => {
    const { store, scope, componentId } = await make();
    const now = new Date('2026-10-19T00:00:00Z');
    const report: Heartbeat = {
      ...scope,
      componentId,
      status: 'unavailable',
      occurredAt: now,
      receivedAt: now,
      expiresAt: new Date(+now + 30 * 86400000),
    };
    await store.transaction(scope.orgId, (tx) => tx.recordHeartbeat(report));
    await store.transaction(scope.orgId, (tx) =>
      tx.recordHeartbeat({ ...report, status: 'healthy', receivedAt: new Date(+now + 1000) }),
    );
    await store.transaction(scope.orgId, (tx) =>
      tx.recordHeartbeat({ ...report, status: 'healthy', occurredAt: new Date(+now - 1000) }),
    );
    expect(await store.getHeartbeat(scope, componentId)).toEqual(report);
    expect(
      await store.getHeartbeat({ ...scope, orgId: 'org_' + 'f'.repeat(24) }, componentId),
    ).toBeUndefined();
    await expect(
      store.transaction(scope.orgId, async (tx) => {
        await tx.recordHeartbeat({
          ...report,
          status: 'healthy',
          occurredAt: new Date(+now + 1000),
          receivedAt: new Date(+now + 1000),
        });
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.getHeartbeat(scope, componentId)).toEqual(report);
    await store.transaction(scope.orgId, (tx) =>
      tx.recordHeartbeat({
        ...report,
        status: 'healthy',
        occurredAt: new Date(+now + 1000),
        receivedAt: new Date(+now + 1000),
      }),
    );
    expect((await store.getHeartbeat(scope, componentId))?.status).toBe('healthy');
    await store.transaction(scope.orgId, (tx) =>
      tx.addEventAggregate({
        ...scope,
        componentId,
        type: 'component.heartbeat',
        outcome: 'healthy',
        hour: now,
        count: 2,
        expiresAt: new Date(+now + 90 * 86400000),
      }),
    );
    expect(
      (await store.listHealthHistory(scope, componentId, now, new Date(+now + 3600000), now))[0]
        ?.count,
    ).toBe(2);
    expect(
      await store.listHealthHistory(
        { ...scope, environmentId: 'ope_' + 'f'.repeat(24) },
        componentId,
        now,
        new Date(+now + 3600000),
        now,
      ),
    ).toEqual([]);
    expect(
      await store.listHealthHistory(
        scope,
        componentId,
        now,
        new Date(+now + 3600000),
        new Date(+now + 91 * 86400000),
      ),
    ).toEqual([]);

    await store.transaction(scope.orgId, (tx) =>
      tx.pruneEventMetadata(scope.orgId, new Date(+report.expiresAt + 1), 1000),
    );
    expect(await store.getHeartbeat(scope, componentId)).toBeUndefined();
  });
}
