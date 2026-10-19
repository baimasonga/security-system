import { InMemoryPrivilegedStore } from '../src/index.ts';
import { privilegedStoreContract } from './store-contract.ts';

privilegedStoreContract('in-memory', () => {
  const store = new InMemoryPrivilegedStore();
  return { store, audited: async () => store.committedAudit.map((e) => e.action) };
});
