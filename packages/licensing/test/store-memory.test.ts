import { InMemoryAuditLog } from '@trust/audit';
import { InMemoryLicensingStore } from '../src/index.ts';
import { licensingStoreContract } from './store-contract.ts';

licensingStoreContract('in-memory', () => {
  const audit = new InMemoryAuditLog({ now: () => new Date('2026-01-01T00:00:00Z') });
  return {
    store: new InMemoryLicensingStore({ audit }),
    seedOrg: async () => {},
    seedUser: async () => {},
    audited: async () => (await audit.list()).map((e) => e.action),
  };
});
