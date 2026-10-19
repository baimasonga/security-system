import { describe, expect, it } from 'vitest';
import type { Application, InventoryStore } from '../src/model.ts';
export const application = (
  id = 'opa_' + 'a'.repeat(24),
  orgId = 'org_' + 'a'.repeat(24),
): Application => ({
  id,
  orgId,
  code: 'rokela-pdf',
  state: 'active',
  version: 1,
  createdAt: new Date('2026-10-19T00:00:00Z'),
  updatedAt: new Date('2026-10-19T00:00:00Z'),
  ownerUserId: 'usr_' + 'a'.repeat(24),
  criticality: 'high',
  productId: null,
});
export function inventoryStoreContract(make: () => Promise<InventoryStore>) {
  describe('inventory store contract', () => {
    it('rejects nonexistent and mismatched ancestors in every adapter', async () => {
      const store = await make();
      const row = application();
      const env = {
        id: 'ope_' + 'a'.repeat(24),
        orgId: row.orgId,
        code: 'staging',
        state: 'active' as const,
        version: 1,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
        applicationId: row.id,
        kind: 'staging' as const,
      };
      await expect(
        store.transaction(row.orgId, (tx) => tx.insert('environment', env)),
      ).rejects.toThrow();
      await store.transaction(row.orgId, async (tx) => {
        await tx.insert('application', row);
        await tx.insert('environment', env);
      });
      const component = {
        ...env,
        id: 'opm_' + 'a'.repeat(24),
        kind: 'service' as const,
        environmentId: env.id,
        dependencyIds: [],
      };
      await expect(
        store.transaction(row.orgId, (tx) =>
          tx.insert('component', { ...component, applicationId: 'opa_' + 'f'.repeat(24) }),
        ),
      ).rejects.toThrow();
      await store.transaction(row.orgId, (tx) => tx.insert('component', component));
      expect(
        await store.list('component', {
          orgId: row.orgId,
          applicationId: row.id,
          environmentId: env.id,
        }),
      ).toEqual([component]);
    });

    it('scopes reads, preserves tombstones, rejects duplicate code and immutable/version changes', async () => {
      const store = await make();
      const row = application();
      await store.transaction(row.orgId, (tx) => tx.insert('application', row));
      expect(await store.find('application', 'org_other', row.id)).toBeUndefined();
      expect(await store.list('application', { orgId: 'org_other' })).toEqual([]);
      await expect(
        store.transaction(row.orgId, (tx) =>
          tx.insert('application', { ...row, id: 'opa_' + 'b'.repeat(24) }),
        ),
      ).rejects.toThrow();
      await expect(
        store.transaction(row.orgId, (tx) =>
          tx.update('application', { ...row, code: 'changed', version: 2 }, 1),
        ),
      ).rejects.toThrow();
      await expect(
        store.transaction(row.orgId, (tx) => tx.update('application', { ...row, version: 3 }, 2)),
      ).rejects.toThrow();
      await store.transaction(row.orgId, (tx) =>
        tx.update('application', { ...row, state: 'archived', version: 2 }, 1),
      );
      expect((await store.find('application', row.orgId, row.id))?.state).toBe('archived');
      await expect(
        store.transaction(row.orgId, (tx) => tx.update('application', { ...row, version: 3 }, 2)),
      ).rejects.toThrow();
      await expect(
        store.transaction(row.orgId, (tx) =>
          tx.insert('application', { ...row, id: 'opa_' + 'c'.repeat(24) }),
        ),
      ).rejects.toThrow();
    });
    it('rolls back writes and audit intent together and serializes competing writers', async () => {
      const store = await make();
      const row = application();
      await expect(
        store.transaction(row.orgId, async (tx) => {
          await tx.insert('application', row);
          await tx.audit.append({
            actor: { type: 'system' },
            action: 'operations.test',
            orgId: row.orgId,
          });
          throw new Error('abort');
        }),
      ).rejects.toThrow('abort');
      expect(await store.find('application', row.orgId, row.id)).toBeUndefined();
      const results = await Promise.allSettled(
        [1, 2].map(() => store.transaction(row.orgId, (tx) => tx.insert('application', row))),
      );
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      expect(await store.list('application', { orgId: row.orgId })).toHaveLength(1);
    });
  });
}
