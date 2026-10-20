import { automationStoreContract } from '../../../packages/operations/test/automation-store-contract.ts';
import { incidentStoreContract } from '../../../packages/operations/test/incident-store-contract.ts';
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
incidentStoreContract(seeded);
automationStoreContract(seeded);
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

it('incident storm deduplicates, guards SQL transitions and rolls back a failed audit', async () => {
  const { pool, store, scope, componentId, app } = await seeded();
  const { IncidentService } = await import('@trust/operations');
  const principal = {
    kind: 'user' as const,
    userId: app.ownerUserId,
    sessionId: 'test-session',
    platformRole: 'none' as const,
  };
  const authority = {
    authorize: async () => {},
    assertWritable: async () => {},
    sessionActive: async () => true,
    activeMember: async () => true,
    activeProduct: async () => true,
  };
  const service = new IncidentService({ store, clock, enabled: () => true, authority });
  const opened = await Promise.all(
    Array.from({ length: 20 }, () =>
      service.open(principal, scope, {
        componentId,
        severity: 'warning',
        reason: 'security_response',
      }),
    ),
  );
  expect(opened.filter((r) => r.created)).toHaveLength(1);
  const row = opened[0]!.incident;
  const edits = await Promise.allSettled(
    Array.from({ length: 20 }, () =>
      service.act(principal, scope, row.id, {
        action: 'acknowledge',
        expectedVersion: 1,
        reason: 'incident_ack',
      }),
    ),
  );
  expect(edits.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  expect(edits.filter((r) => r.status === 'rejected')).toHaveLength(19);
  for (const sql of [
    "UPDATE operations_incidents SET state='open',version=version+1 WHERE id=$1",
    "UPDATE operations_incidents SET severity='critical',version=version+1 WHERE id=$1",
    'UPDATE operations_incidents SET version=version+2 WHERE id=$1',
  ])
    await expect(pool.query(sql, [row.id])).rejects.toThrow();
  if (appRoleMode()) {
    await expect(
      pool.query('DELETE FROM operations_incidents WHERE id=$1', [row.id]),
    ).rejects.toThrow(/retention protected/);
    await expect(pool.query('TRUNCATE operations_incidents')).rejects.toThrow(/permission denied/);
  }
  const failing = {
    query: pool.query.bind(pool),
    async connect() {
      const client = await pool.connect(),
        query = client.query.bind(client);
      return new Proxy(client, {
        get(target, key) {
          if (key === 'query')
            return async (sql: string, params?: unknown[]) => {
              if (sql.includes('INSERT INTO audit_events'))
                throw new Error('incident_audit_failure');
              return query(sql, params);
            };
          const value = Reflect.get(target, key);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
  const broken = new IncidentService({
    store: new PgInventoryStore(failing, clock),
    clock,
    enabled: () => true,
    authority,
  });
  await expect(
    broken.act(principal, scope, row.id, {
      action: 'resolve',
      expectedVersion: 2,
      reason: 'incident_resolution',
    }),
  ).rejects.toThrow('incident_audit_failure');
  expect((await store.findIncident(scope.orgId, row.id))?.state).toBe('acknowledged');
  const audits = await pool.query(
    "SELECT action FROM audit_events WHERE action LIKE 'operations.incident.%' ORDER BY seq",
  );
  expect(audits.rows.map((r) => r.action)).toEqual([
    'operations.incident.opened',
    'operations.incident.acknowledged',
  ]);
});

it('persists automatic storm deduplication, atomic intents, recovery and fenced retry across workers', async () => {
  const { AutomationService } = await import('@trust/operations');
  const f = await seeded();
  let now = +clock.now();
  const rule = {
    ...f.scope,
    id: 'opr_' + 'a'.repeat(24),
    componentId: f.componentId,
    kind: 'heartbeat' as const,
    eventType: null,
    threshold: 1,
    windowSeconds: 60,
    severity: 'warning' as const,
    runbook: 'check_scanner' as const,
    enabled: true,
    maintenanceUntil: null,
    createdByUserId: 'usr_' + 'a'.repeat(24),
    version: 1,
    createdAt: new Date(now),
    updatedAt: new Date(now),
    evaluatedAt: null,
    badSince: null,
    recoverySince: null,
    incidentId: null,
    observation: 'unknown' as const,
    observedCount: 0,
  };
  await f.store.transaction(f.scope.orgId, (tx) => tx.insertAlertRule(rule));
  const authority = {
    authorize: async () => {},
    assertWritable: async () => {},
    activeMember: async () => true,
    activeProduct: async () => true,
    sessionActive: async () => true,
  };
  let attempts = 0;
  const service = new AutomationService({
    store: f.store,
    clock: { now: () => new Date(now) },
    enabled: () => true,
    authority,
    deliver: async () => {
      attempts++;
      if (attempts === 1) throw new Error('synthetic provider failure');
    },
  });
  const report = async (status: 'healthy' | 'unavailable') =>
    f.store.transaction(f.scope.orgId, (tx) =>
      tx.recordHeartbeat({
        ...f.scope,
        componentId: f.componentId,
        status,
        occurredAt: new Date(now),
        receivedAt: new Date(now),
        expiresAt: new Date(now + 86400000),
      }),
    );
  await report('unavailable');
  await service.evaluate(f.scope);
  now += 60000;
  await Promise.all(Array.from({ length: 20 }, () => service.evaluate(f.scope)));
  const incidents = await f.store.listIncidents(f.scope, { limit: 100 });
  expect(incidents).toHaveLength(1);
  expect(incidents[0]?.ruleId).toBe(rule.id);
  expect(await f.store.listAlertNotifications(f.scope)).toHaveLength(1);
  await service.deliverPending(f.scope);
  expect((await f.store.listAlertNotifications(f.scope))[0]?.state).toBe('pending');
  now += 300000;
  await Promise.all([service.deliverPending(f.scope), service.deliverPending(f.scope)]);
  expect(attempts).toBe(2);
  expect((await f.store.listAlertNotifications(f.scope))[0]?.state).toBe('delivered');
  await report('healthy');
  await service.evaluate(f.scope);
  now += 60000;
  await report('healthy');
  await service.evaluate(f.scope);
  expect((await f.store.findIncident(f.scope.orgId, incidents[0]!.id))?.state).toBe('resolved');
  expect(await f.store.listAlertNotifications(f.scope)).toHaveLength(2);
  await expect(
    f.pool.query('UPDATE operations_alert_rules SET threshold=2,version=version+1 WHERE id=$1', [
      rule.id,
    ]),
  ).rejects.toThrow();
  await expect(
    f.pool.query('DELETE FROM operations_incidents WHERE id=$1', [incidents[0]!.id]),
  ).rejects.toThrow(/retention protected/);
  const note = (await f.store.listAlertNotifications(f.scope))[0]!;
  await expect(
    f.pool.query(
      "UPDATE operations_alert_notifications SET state='pending',delivered_at=NULL WHERE id=$1",
      [note.id],
    ),
  ).rejects.toThrow();
  const audit = (
    await f.pool.query(
      "SELECT action FROM audit_events WHERE action LIKE 'operations.incident.%' ORDER BY seq",
    )
  ).rows;
  expect(audit.map((r) => r.action)).toEqual([
    'operations.incident.opened',
    'operations.incident.resolved',
  ]);
});
