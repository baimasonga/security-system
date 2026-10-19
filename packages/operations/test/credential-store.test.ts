import { InMemoryInventoryStore } from '../src/index.ts';
import { application } from './store-contract.ts';
import { credentialStoreContract } from './credential-store-contract.ts';
credentialStoreContract(async () => {
  const store = new InMemoryInventoryStore();
  const app = application();
  const env = {
    id: 'ope_' + 'a'.repeat(24),
    orgId: app.orgId,
    applicationId: app.id,
    code: 'staging',
    kind: 'staging' as const,
    state: 'active' as const,
    version: 1,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
  };
  await store.transaction(app.orgId, async (tx) => {
    await tx.insert('application', app);
    await tx.insert('environment', env);
  });
  return { store, scope: { orgId: app.orgId, applicationId: app.id, environmentId: env.id } };
});
