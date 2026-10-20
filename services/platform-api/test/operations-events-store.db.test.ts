import { healthStoreContract } from '../../../packages/operations/test/health-store-contract.ts';
import {
  eventIngestionContract,
  eventRevokeRaceContract,
} from '../../../packages/operations/test/event-ingestion-contract.ts';
import { CredentialService, EventService, HealthService } from '@trust/operations';
import { sha256Hex } from '@trust/crypto';
import { expect, it } from 'vitest';
import { createSchemaPool, appRoleMode } from '../../../tests/support/pg.ts';
import { eventStoreContract } from '../../../packages/operations/test/event-store-contract.ts';
import { application } from '../../../packages/operations/test/store-contract.ts';
import type { CredentialScope } from '@trust/operations';
import { PgInventoryStore } from '../src/db/pg-operations-store.ts';
const clock = { now: () => new Date('2026-10-19T00:00:00Z') };
async function seeded() {
  const pool = createSchemaPool();
  const app = application();
  await pool.query(
    "INSERT INTO users (id,email,password_hash,status,platform_role) VALUES ($1,'owner@example.test','test-only','active','none')",
    [app.ownerUserId],
  );
  await pool.query("INSERT INTO organizations (id,name,kind) VALUES ($1,'test','team')", [
    app.orgId,
  ]);
  await pool.query("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", [
    app.orgId,
    app.ownerUserId,
  ]);
  await pool.query(
    "INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at) VALUES ('test-session',$1,'test-only',$2,$3)",
    [app.ownerUserId, clock.now(), new Date(+clock.now() + 86400000)],
  );
  const store = new PgInventoryStore(pool, clock);
  const scope: CredentialScope = {
    orgId: app.orgId,
    applicationId: app.id,
    environmentId: 'ope_' + 'a'.repeat(24),
  };
  await store.transaction(app.orgId, async (tx) => {
    await tx.insert('application', app);
    await tx.insert('environment', {
      id: scope.environmentId,
      orgId: app.orgId,
      applicationId: app.id,
      code: 'staging',
      kind: 'staging',
      state: 'active',
      version: 1,
      createdAt: clock.now(),
      updatedAt: clock.now(),
    });
  });
  const componentId = 'opm_' + 'a'.repeat(24);
  await store.transaction(app.orgId, async (tx) => {
    await tx.insert('component', {
      ...scope,
      id: componentId,
      code: 'converter',
      kind: 'worker',
      state: 'active',
      version: 1,
      createdAt: clock.now(),
      updatedAt: clock.now(),
      dependencyIds: [],
    });
    await tx.insertCredential({
      ...scope,
      id: 'opc_' + 'a'.repeat(32),
      purpose: 'events:write',
      source: 'backend_report',
      secretHash: sha256Hex('c'.repeat(64)),
      createdAt: clock.now(),
      expiresAt: new Date(+clock.now() + 86400000),
      revokedAt: null,
      rotatedAt: null,
    });
  });
  return { pool, store, scope, app, componentId };
}
eventStoreContract(seeded);
it('requires ancestor-consistent event provenance and prevents app-role evidence updates', async () => {
  const { pool, store, scope, componentId } = await seeded();
  const event = {
    ...scope,
    id: '00000000-0000-4000-8000-000000000001',
    componentId,
    credentialId: 'opc_' + 'a'.repeat(32),
    source: 'backend_report' as const,
    type: 'component.heartbeat',
    attributes: { status: 'healthy' },
    occurredAt: clock.now().toISOString(),
    receivedAt: clock.now(),
    expiresAt: new Date(+clock.now() + 30 * 86400000),
    contentHash: 'c'.repeat(64),
    sizeBytes: 600,
  };
  await expect(
    store.transaction(scope.orgId, (tx) =>
      tx.insertEvent({ ...event, componentId: 'opm_' + 'f'.repeat(24) }),
    ),
  ).rejects.toThrow();
  await store.transaction(scope.orgId, (tx) => tx.insertEvent(event));
  if (appRoleMode())
    await expect(
      pool.query('UPDATE operations_events SET content_hash=$1 WHERE id=$2', [
        'd'.repeat(64),
        event.id,
      ]),
    ).rejects.toThrow();
});

eventIngestionContract(async () => {
  const f = await seeded();
  const credentials = new CredentialService({
    store: f.store,
    clock,
    enabled: () => true,
    authorize: async () => {},
    assertWritable: async () => {},
    stepUp: async () => {},
    sessionActive: async () => true,
  });
  return {
    ...f,
    events: new EventService({ store: f.store, credentials, clock, enabled: () => true }),
    token: 'ops_v1.opc_' + 'a'.repeat(32) + '.' + 'c'.repeat(64),
    now: clock.now,
  };
});

eventRevokeRaceContract(async () => {
  const f = await seeded();
  const credentials = new CredentialService({
    store: f.store,
    clock,
    enabled: () => true,
    authorize: async () => {},
    assertWritable: async () => {},
    stepUp: async () => {},
    sessionActive: async () => true,
  });
  return {
    ...f,
    events: new EventService({ store: f.store, credentials, clock, enabled: () => true }),
    token: 'ops_v1.opc_' + 'a'.repeat(32) + '.' + 'c'.repeat(64),
    now: clock.now,
  };
});

healthStoreContract(seeded);
it('keeps stale health across PG-backed service reconstruction and refuses clock rewrites', async () => {
  const f = await seeded();
  let now = clock.now();
  const principal = {
    kind: 'user' as const,
    userId: f.app.ownerUserId,
    sessionId: 'test-session',
    platformRole: 'none' as const,
  };
  const service = () =>
    new HealthService({
      store: f.store,
      clock: { now: () => now },
      enabled: () => true,
      authorize: async () => {},
    });
  await f.store.transaction(f.scope.orgId, (tx) =>
    tx.recordHeartbeat({
      ...f.scope,
      componentId: f.componentId,
      status: 'healthy',
      occurredAt: now,
      receivedAt: now,
      expiresAt: new Date(+now + 86400000),
    }),
  );
  expect((await service().snapshot(principal, f.scope)).components[0]?.status).toBe('healthy');
  now = new Date(+now + 180000);
  expect((await service().snapshot(principal, f.scope)).components[0]?.status).toBe('stale');
  now = new Date(+now - 120000);
  expect((await service().snapshot(principal, f.scope)).components[0]?.status).toBe('stale');
  await expect(
    f.pool.query('UPDATE operations_accounts SET health_observed_at=$2 WHERE org_id=$1', [
      f.scope.orgId,
      now,
    ]),
  ).rejects.toThrow(/cannot regress/);
  await expect(
    f.pool.query('UPDATE operations_accounts SET health_observed_at=NULL WHERE org_id=$1', [
      f.scope.orgId,
    ]),
  ).rejects.toThrow(/cannot regress/);
});
