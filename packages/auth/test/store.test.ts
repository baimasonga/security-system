import { InMemoryAuthStore } from '../src/index.ts';
import { authStoreContract } from './store-contract.ts';

authStoreContract('in-memory', () => new InMemoryAuthStore());
