import { expect, it } from 'vitest';
import type { CredentialScope, InventoryStore } from '../src/model.ts';
import type { Heartbeat, ProbeResult } from '../src/health.ts';
export function healthStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope; componentId: string }>,
) {
  it('persists a monotonic health assessment clock and rolls it back with its transaction', async () => {
    const { store, scope } = await make();
    const now = new Date('2026-10-19T00:00:00Z');
    const observed = new Date(+now + 180000);
    expect(
      await store.transaction(scope.orgId, (tx) => tx.observeHealthTime(scope.orgId, now)),
    ).toEqual(now);
    expect(
      await store.transaction(scope.orgId, (tx) => tx.observeHealthTime(scope.orgId, observed)),
    ).toEqual(observed);
    expect(
      await store.transaction(scope.orgId, (tx) => tx.observeHealthTime(scope.orgId, now)),
    ).toEqual(observed);
    await expect(
      store.transaction(scope.orgId, async (tx) => {
        await tx.observeHealthTime(scope.orgId, new Date(+observed + 86400000));
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(
      await store.transaction(scope.orgId, (tx) => tx.observeHealthTime(scope.orgId, now)),
    ).toEqual(observed);
  });
  it('keeps Warrior probe results separate from backend reports, ordered, scoped and transactional', async () => {
    const { store, scope, componentId } = await make();
    const now = new Date('2026-10-19T00:00:00Z');
    const result: ProbeResult = {
      ...scope,
      componentId,
      status: 'unavailable',
      occurredAt: now,
      receivedAt: new Date(+now + 2000),
      expiresAt: new Date(+now + 30 * 86400000),
    };
    await store.transaction(scope.orgId, (tx) => tx.recordProbeResult(result));
    // A tie prefers unavailable; an older probe never replaces a newer one.
    await store.transaction(scope.orgId, (tx) =>
      tx.recordProbeResult({ ...result, status: 'healthy' }),
    );
    await store.transaction(scope.orgId, (tx) =>
      tx.recordProbeResult({ ...result, status: 'healthy', occurredAt: new Date(+now - 1000) }),
    );
    expect(await store.getProbeResult(scope, componentId)).toEqual(result);
    // A probe is not a backend report and a backend report is not a probe.
    expect(await store.getHeartbeat(scope, componentId)).toBeUndefined();
    await store.transaction(scope.orgId, (tx) =>
      tx.recordHeartbeat({
        ...scope,
        componentId,
        status: 'healthy',
        occurredAt: new Date(+now + 5000),
        receivedAt: new Date(+now + 5000),
        expiresAt: new Date(+now + 86400000),
      }),
    );
    expect(await store.getProbeResult(scope, componentId)).toEqual(result);
    expect(
      await store.getProbeResult({ ...scope, orgId: 'org_' + 'f'.repeat(24) }, componentId),
    ).toBeUndefined();
    const later = {
      ...result,
      status: 'healthy' as const,
      occurredAt: new Date(+now + 60000),
      receivedAt: new Date(+now + 61000),
    };
    await expect(
      store.transaction(scope.orgId, async (tx) => {
        await tx.recordProbeResult(later);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.getProbeResult(scope, componentId)).toEqual(result);
    await store.transaction(scope.orgId, (tx) => tx.recordProbeResult(later));
    expect(await store.getProbeResult(scope, componentId)).toEqual(later);
    // A result must not claim an occurrence after its receipt or more than 120 s before it.
    for (const bad of [
      { ...later, occurredAt: new Date(+later.receivedAt + 1) },
      { ...later, occurredAt: new Date(+later.receivedAt - 120001) },
      { ...later, expiresAt: later.receivedAt },
    ])
      await expect(
        store.transaction(scope.orgId, (tx) => tx.recordProbeResult(bad)),
      ).rejects.toThrow();
    await expect(
      store.transaction(scope.orgId, (tx) =>
        tx.recordProbeResult({ ...later, componentId: 'opm_' + 'f'.repeat(24) }),
      ),
    ).rejects.toThrow();
  });
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
