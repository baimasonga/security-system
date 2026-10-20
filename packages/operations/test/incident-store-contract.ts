import { expect, it } from 'vitest';
import type { CredentialScope, InventoryStore, Incident } from '../src/index.ts';
export function incidentStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope; componentId: string }>,
) {
  it('scopes durable incidents, rejects active duplicates and preserves transactional rollback', async () => {
    const { store, scope, componentId } = await make();
    const now = new Date('2026-10-20T00:00:00Z');
    const row: Incident = {
      ...scope,
      id: 'opi_' + 'a'.repeat(24),
      componentId,
      source: 'manual_triage',
      severity: 'warning',
      state: 'open',
      assigneeUserId: null,
      createdByUserId: 'usr_' + 'a'.repeat(24),
      version: 1,
      createdAt: now,
      updatedAt: now,
      acknowledgedAt: null,
      resolvedAt: null,
    };
    await store.transaction(scope.orgId, (tx) => tx.insertIncident(row));
    expect(await store.findIncident(scope.orgId, row.id)).toEqual(row);
    expect(await store.findIncident('org_' + 'f'.repeat(24), row.id)).toBeUndefined();
    expect(
      await store.listIncidents(
        { ...scope, environmentId: 'ope_' + 'f'.repeat(24) },
        { limit: 10 },
      ),
    ).toEqual([]);
    await expect(
      store.transaction(scope.orgId, (tx) =>
        tx.insertIncident({ ...row, id: 'opi_' + 'b'.repeat(24) }),
      ),
    ).rejects.toThrow();
    await expect(
      store.transaction(scope.orgId, async (tx) => {
        await tx.updateIncident(
          { ...row, state: 'acknowledged', acknowledgedAt: now, version: 2 },
          1,
        );
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect((await store.findIncident(scope.orgId, row.id))?.state).toBe('open');
    await expect(
      store.transaction(scope.orgId, (tx) =>
        tx.updateIncident({ ...row, version: 2, componentId: 'opm_' + 'f'.repeat(24) }, 1),
      ),
    ).rejects.toThrow();
    await store.transaction(scope.orgId, (tx) =>
      tx.updateIncident({ ...row, state: 'resolved', resolvedAt: now, version: 2 }, 1),
    );
    await expect(
      store.transaction(scope.orgId, (tx) => tx.updateIncident({ ...row, version: 3 }, 2)),
    ).rejects.toThrow();
    await store.transaction(scope.orgId, (tx) =>
      tx.insertIncident({ ...row, id: 'opi_' + 'b'.repeat(24) }),
    );
    expect((await store.listIncidents(scope, { limit: 1 }))[0]?.id).toBe(row.id);
    expect((await store.listIncidents(scope, { limit: 1, after: row.id }))[0]?.id).toBe(
      'opi_' + 'b'.repeat(24),
    );
  });
}
