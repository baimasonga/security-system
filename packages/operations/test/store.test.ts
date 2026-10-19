import { InMemoryInventoryStore } from '../src/index.ts';
import { inventoryStoreContract } from './store-contract.ts';
inventoryStoreContract(async () => new InMemoryInventoryStore());

import { expect, it, vi } from 'vitest';
import { InMemoryAuditLog } from '@trust/audit';
import { application } from './store-contract.ts';
it('memory commit is refused and state stays private when audit persistence fails', async () => {
  const audit = new InMemoryAuditLog({ now: () => new Date() });
  const store = new InMemoryInventoryStore({ audit });
  const row = application();
  vi.spyOn(audit, 'appendMany').mockRejectedValueOnce(new Error('audit unavailable'));
  await expect(
    store.transaction(row.orgId, async (tx) => {
      await tx.insert('application', row);
      await tx.audit.append({
        actor: { type: 'system' },
        action: 'operations.application.created',
        orgId: row.orgId,
      });
    }),
  ).rejects.toThrow('audit unavailable');
  expect(await store.find('application', row.orgId, row.id)).toBeUndefined();
  expect(await audit.list({ orgId: row.orgId })).toEqual([]);
});
