import { expect, it, vi } from 'vitest';
import { DomainError } from '@trust/shared-types';
import { IncidentService } from '../src/incidents.ts';
import { eventFixture } from './event-fixture.ts';
import { incidentStoreContract } from './incident-store-contract.ts';
incidentStoreContract(eventFixture);
const p = {
  kind: 'user' as const,
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'session',
  platformRole: 'none' as const,
};
async function setup() {
  const f = await eventFixture();
  const authority = {
    authorize: vi.fn(async () => {}),
    assertWritable: vi.fn(async () => {}),
    activeMember: vi.fn(async () => true),
    activeProduct: vi.fn(async () => true),
    sessionActive: vi.fn(async () => true),
  };
  const d = { store: f.store, clock: { now: f.now }, enabled: () => true, authority };
  return { ...f, authority, d, service: new IncidentService(d) };
}
it('deduplicates a storm, audits transitions, rejects stale edits and requires same-org assignees', async () => {
  const f = await setup();
  const input = {
    componentId: f.componentId,
    severity: 'warning' as const,
    reason: 'security_response' as const,
  };
  const opening = Promise.all(Array.from({ length: 20 }, () => f.service.open(p, f.scope, input)));
  await expect(opening).resolves.toHaveLength(20);
  const opened = await opening;
  expect(opened.filter((r) => r.created)).toHaveLength(1);
  expect(new Set(opened.map((r) => r.incident.id)).size).toBe(1);
  const row = opened[0]!.incident;
  f.authority.activeMember.mockResolvedValue(false);
  await expect(
    f.service.act(p, f.scope, row.id, {
      action: 'assign',
      expectedVersion: 1,
      reason: 'assignment',
      assigneeUserId: 'usr_' + 'b'.repeat(24),
    }),
  ).rejects.toMatchObject({ code: 'not_found' });
  expect((await f.store.findIncident(f.scope.orgId, row.id))?.version).toBe(1);
  f.authority.activeMember.mockResolvedValue(true);
  const assigned = await f.service.act(p, f.scope, row.id, {
    action: 'assign',
    expectedVersion: 1,
    reason: 'assignment',
    assigneeUserId: p.userId,
  });
  expect(assigned.assigneeUserId).toBe(p.userId);
  expect(
    (await f.audit.list()).find((e) => e.action === 'operations.incident.assigned')?.metadata,
  ).toMatchObject({ from_assignee_user_id: null, to_assignee_user_id: p.userId });
  await expect(
    f.service.act(p, f.scope, row.id, {
      action: 'acknowledge',
      expectedVersion: 1,
      reason: 'incident_ack',
    }),
  ).rejects.toMatchObject({ code: 'conflict' });
  const ack = await f.service.act(p, f.scope, row.id, {
    action: 'acknowledge',
    expectedVersion: 2,
    reason: 'incident_ack',
  });
  expect(ack.state).toBe('acknowledged');
  const closed = await f.service.act(p, f.scope, row.id, {
    action: 'resolve',
    expectedVersion: 3,
    reason: 'incident_resolution',
  });
  expect(closed.state).toBe('resolved');
  await expect(
    f.service.act(p, f.scope, row.id, {
      action: 'assign',
      expectedVersion: 4,
      reason: 'assignment',
      assigneeUserId: null,
    }),
  ).rejects.toMatchObject({ code: 'conflict' });
  expect((await f.service.open(p, f.scope, input)).incident.id).not.toBe(row.id);
  expect(
    (await f.audit.list())
      .filter((e) => e.action.startsWith('operations.incident.'))
      .map((e) => e.action),
  ).toEqual([
    'operations.incident.opened',
    'operations.incident.assigned',
    'operations.incident.acknowledged',
    'operations.incident.resolved',
    'operations.incident.opened',
  ]);
});
it('fails closed on flag, membership, sessions, freezes, inactive parents and wrong scope', async () => {
  const f = await setup();
  const input = {
    componentId: f.componentId,
    severity: 'warning' as const,
    reason: 'security_response' as const,
  };
  await expect(
    new IncidentService({ ...f.d, enabled: () => false }).open(p, f.scope, input),
  ).rejects.toMatchObject({ code: 'not_found' });
  f.authority.authorize.mockRejectedValueOnce(new DomainError('forbidden', 'request rejected'));
  await expect(f.service.open(p, f.scope, input)).rejects.toMatchObject({ code: 'forbidden' });
  f.authority.sessionActive.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
  await expect(f.service.open(p, f.scope, input)).rejects.toMatchObject({
    code: 'unauthenticated',
  });
  f.authority.assertWritable.mockRejectedValueOnce(new DomainError('frozen', 'request rejected'));
  await expect(f.service.open(p, f.scope, input)).rejects.toMatchObject({ code: 'forbidden' });
  await expect(
    f.service.open(p, { ...f.scope, environmentId: 'ope_' + 'f'.repeat(24) }, input),
  ).rejects.toMatchObject({ code: 'not_found' });
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const old = (await tx.find('component', f.scope.orgId, f.componentId))!;
    await tx.update('component', { ...old, state: 'disabled', version: 2 }, 1);
  });
  await expect(f.service.open(p, f.scope, input)).rejects.toMatchObject({ code: 'conflict' });
  expect((await f.service.list(p, f.scope, { limit: 10 })).items).toEqual([]);
});

it('rolls back incident state and audit together if audit persistence fails', async () => {
  const f = await setup();
  const count = (await f.audit.list()).length;
  vi.spyOn(f.audit, 'appendMany').mockRejectedValueOnce(new Error('audit_failure'));
  await expect(
    f.service.open(p, f.scope, {
      componentId: f.componentId,
      severity: 'warning',
      reason: 'security_response',
    }),
  ).rejects.toThrow('audit_failure');
  expect(await f.store.listIncidents(f.scope, { limit: 10 })).toEqual([]);
  expect((await f.audit.list()).length).toBe(count);
});

it('requires correct reasons, caps retained rows, preserves monotonic edit time and scope', async () => {
  const f = await setup();
  const input = {
    componentId: f.componentId,
    severity: 'warning' as const,
    reason: 'security_response' as const,
  };
  await expect(
    f.service.open(p, f.scope, { ...input, reason: '' as 'security_response' }),
  ).rejects.toMatchObject({ code: 'invalid_request' });
  const row = (await f.service.open(p, f.scope, input)).incident;
  await expect(
    f.service.act(p, { ...f.scope, environmentId: 'ope_' + 'f'.repeat(24) }, row.id, {
      action: 'resolve',
      expectedVersion: 1,
      reason: 'incident_resolution',
    }),
  ).rejects.toMatchObject({ code: 'not_found' });
  await expect(
    f.service.act(p, f.scope, row.id, {
      action: 'acknowledge',
      expectedVersion: 1,
      reason: 'assignment' as 'incident_ack',
    }),
  ).rejects.toMatchObject({ code: 'invalid_request' });
  f.advance(2000);
  const assigned = await f.service.act(p, f.scope, row.id, {
    action: 'assign',
    expectedVersion: 1,
    reason: 'assignment',
    assigneeUserId: p.userId,
  });
  f.advance(-1000);
  const acknowledging = f.service.act(p, f.scope, row.id, {
    action: 'acknowledge',
    expectedVersion: 2,
    reason: 'incident_ack',
  });
  await expect(acknowledging).resolves.toMatchObject({ state: 'acknowledged' });
  const ack = await acknowledging;
  expect(+ack.updatedAt).toBeGreaterThanOrEqual(+assigned.updatedAt);
  await f.service.act(p, f.scope, row.id, {
    action: 'resolve',
    expectedVersion: 3,
    reason: 'incident_resolution',
  });
  await f.store.transaction(f.scope.orgId, async (tx) => {
    for (let i = 1; i < 1000; i++) {
      const r = { ...row, id: 'opi_' + i.toString(16).padStart(24, '0') };
      await tx.insertIncident(r);
      await tx.updateIncident({ ...r, state: 'resolved', resolvedAt: r.createdAt, version: 2 }, 1);
    }
  });
  await expect(f.service.open(p, f.scope, input)).rejects.toMatchObject({ code: 'quota_exceeded' });
});
