import { vi } from 'vitest';
import { InMemoryAuditLog } from '@trust/audit';
import { type UserPrincipal } from '@trust/shared-types';
import {
  CredentialService,
  InMemoryInventoryStore,
  EventService,
  type CredentialScope,
} from '../src/index.ts';
import { application } from './store-contract.ts';
const principal: UserPrincipal = {
  kind: 'user',
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'test-session',
  platformRole: 'none',
};
export async function eventFixture() {
  let time = new Date('2026-10-19T00:00:00Z');
  const clock = { now: () => time };
  const audit = new InMemoryAuditLog(clock);
  const store = new InMemoryInventoryStore({ audit });
  const app = application();
  const scope: CredentialScope = {
    orgId: app.orgId,
    applicationId: app.id,
    environmentId: 'ope_' + 'a'.repeat(24),
  };
  await store.transaction(app.orgId, async (tx) => {
    await tx.insert('application', app);
    await tx.insert('environment', {
      id: scope.environmentId,
      orgId: scope.orgId,
      applicationId: app.id,
      code: 'staging',
      kind: 'staging',
      state: 'active',
      version: 1,
      createdAt: time,
      updatedAt: time,
    });
  });
  const deps = {
    store,
    clock,
    enabled: () => true,
    authorize: vi.fn(async () => {}),
    assertWritable: vi.fn(async () => {}),
    stepUp: vi.fn(async () => {}),
    sessionActive: vi.fn(async () => true),
  };
  const service = new CredentialService(deps);
  const input = {
    purpose: 'events:write' as const,
    ttlSeconds: 7776000,
    reason: 'initial_setup' as const,
    mfaCode: '123456',
  };
  const componentId = 'opm_' + 'a'.repeat(24);
  await store.transaction(scope.orgId, (tx) =>
    tx.insert('component', {
      ...scope,
      id: componentId,
      code: 'converter',
      kind: 'worker',
      state: 'active',
      version: 1,
      createdAt: time,
      updatedAt: time,
      dependencyIds: [],
    }),
  );
  const events = new EventService({ store, credentials: service, clock, enabled: () => true });
  const issue = () => service.issue(principal, scope, input);
  const valid = (
    token: string,
    expected: Partial<CredentialScope> & { purpose?: string; source?: string } = {},
  ) => service.withCredential(token, expected, async (_tx, identity) => identity);
  return {
    store,
    events,
    componentId,
    scope,
    audit,
    service,
    deps,
    input,
    issue,
    valid,
    advance: (ms: number) => {
      time = new Date(+time + ms);
    },
    now: () => time,
  };
}
