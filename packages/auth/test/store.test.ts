import { InMemoryAuditLog } from '@trust/audit';
import { InMemoryAuthStore } from '../src/index.ts';
import { authStoreContract } from './store-contract.ts';

authStoreContract('in-memory', () => {
  const audit = new InMemoryAuditLog({ now: () => new Date('2026-01-01T00:00:00Z') });
  return {
    store: new InMemoryAuthStore({ audit }),
    audited: async () => (await audit.list()).map((e) => e.action),
  };
});
