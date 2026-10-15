import { randomBytes } from 'node:crypto';
import { InMemorySharingStore } from '../src/index.ts';
import { sharingStoreContract } from './store-contract.ts';

sharingStoreContract('in-memory', () => {
  const store = new InMemorySharingStore();
  return {
    store,
    seed: async () => ({
      orgId: `org_${randomBytes(6).toString('hex')}`,
      userId: `usr_${randomBytes(6).toString('hex')}`,
    }),
    audited: async () => store.committedAudit.map((e) => e.action),
  };
});
