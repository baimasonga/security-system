import { InMemoryLicensingStore } from '../src/index.ts';
import { licensingStoreContract } from './store-contract.ts';

licensingStoreContract('in-memory', () => ({
  store: new InMemoryLicensingStore(),
  seedOrg: async () => {},
  seedUser: async () => {},
}));
