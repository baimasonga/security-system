import { describe, expect, it } from 'vitest';
import type { CredentialRecord, CredentialScope, InventoryStore } from '../src/index.ts';
export function credentialStoreContract(
  make: () => Promise<{ store: InventoryStore; scope: CredentialScope }>,
) {
  describe('operations credential store contract', () => {
    it('scopes lists, persists digests and rolls back credential/audit changes', async () => {
      const { store, scope } = await make();
      const now = new Date('2026-10-19T00:00:00Z');
      const row: CredentialRecord = {
        ...scope,
        id: 'opc_' + 'a'.repeat(32),
        purpose: 'events:write',
        source: 'backend_report',
        secretHash: 'b'.repeat(64),
        createdAt: now,
        expiresAt: new Date(+now + 86400000),
        revokedAt: null,
        rotatedAt: null,
      };
      await expect(
        store.transaction(scope.orgId, async (tx) => {
          await tx.insertCredential(row);
          await tx.audit.append({
            actor: { type: 'system' },
            orgId: scope.orgId,
            action: 'operations.credential.issued',
          });
          throw new Error('abort');
        }),
      ).rejects.toThrow('abort');
      expect(await store.findCredential(row.id)).toBeUndefined();
      await store.transaction(scope.orgId, (tx) => tx.insertCredential(row));
      expect(await store.findCredential(row.id)).toEqual(row);
      expect(await store.listCredentials({ ...scope, orgId: 'org_other' }, { limit: 100 })).toEqual(
        [],
      );
      expect(await store.listCredentials(scope, { limit: 100, activeAt: row.expiresAt })).toEqual(
        [],
      );
      await expect(
        store.transaction(scope.orgId, (tx) =>
          tx.updateCredential({ ...row, secretHash: 'c'.repeat(64) }),
        ),
      ).rejects.toThrow();
      await expect(
        store.transaction(scope.orgId, (tx) =>
          tx.updateCredential({ ...row, expiresAt: new Date(+row.expiresAt + 1) }),
        ),
      ).rejects.toThrow();
      await store.transaction(scope.orgId, (tx) => tx.updateCredential({ ...row, revokedAt: now }));
      expect(await store.listCredentials(scope, { limit: 100, activeAt: now })).toEqual([]);
      await expect(
        store.transaction(scope.orgId, (tx) => tx.updateCredential(row)),
      ).rejects.toThrow();
    });
    it('serializes competing issue decisions and keeps scopes immutable', async () => {
      const { store, scope } = await make();
      const now = new Date('2026-10-19T00:00:00Z');
      const results = await Promise.allSettled(
        [1, 2, 3].map((i) =>
          store.transaction(scope.orgId, async (tx) => {
            const active = await tx.listCredentials(scope, { limit: 3, activeAt: now });
            if (active.length >= 2) throw new Error('cap');
            await tx.insertCredential({
              ...scope,
              id: 'opc_' + String(i).repeat(32),
              purpose: 'events:write',
              source: 'backend_report',
              secretHash: 'a'.repeat(64),
              createdAt: now,
              expiresAt: new Date(+now + 86400000),
              revokedAt: null,
              rotatedAt: null,
            });
          }),
        ),
      );
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
      expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
    });
  });
}
