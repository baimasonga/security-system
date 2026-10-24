import { expect, it, vi } from 'vitest';
import { AutomationService } from '../src/automation.ts';
import { eventFixture } from './event-fixture.ts';
import { automationStoreContract } from './automation-store-contract.ts';
automationStoreContract(eventFixture);
const p = {
  kind: 'user' as const,
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'session',
  platformRole: 'none' as const,
};
async function setup() {
  const f = await eventFixture();
  let now = +f.now();
  const authority = {
    authorize: vi.fn(async () => {}),
    assertWritable: vi.fn(async () => {}),
    activeMember: vi.fn(async () => true),
    activeProduct: vi.fn(async () => true),
    sessionActive: vi.fn(async () => true),
  };
  const deliver = vi.fn(async () => {});
  const service = new AutomationService({
    store: f.store,
    clock: { now: () => new Date(now) },
    authority,
    enabled: () => true,
    deliver,
  });
  const input = {
    componentId: f.componentId,
    kind: 'heartbeat' as const,
    eventType: null,
    threshold: 1,
    windowSeconds: 60,
    severity: 'warning' as const,
    runbook: 'check_scanner' as const,
    reason: 'initial_setup' as const,
  };
  const heartbeat = async (status: 'healthy' | 'unavailable') => {
    await f.store.transaction(f.scope.orgId, (tx) =>
      tx.recordHeartbeat({
        ...f.scope,
        componentId: f.componentId,
        status,
        occurredAt: new Date(now),
        receivedAt: new Date(now),
        expiresAt: new Date(now + 86400000),
      }),
    );
  };
  const probe = async (status: 'healthy' | 'unavailable') => {
    await f.store.transaction(f.scope.orgId, (tx) =>
      tx.recordProbeResult({
        ...f.scope,
        componentId: f.componentId,
        status,
        occurredAt: new Date(now),
        receivedAt: new Date(now),
        expiresAt: new Date(now + 86400000),
      }),
    );
  };
  return {
    ...f,
    authority,
    deliver,
    service,
    input,
    heartbeat,
    probe,
    advance: (ms: number) => {
      now += ms;
    },
  };
}
it('waits for real evidence and a full bad window, deduplicates storms and needs fresh recovery', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation).toBe('unknown');
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toEqual([]);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await Promise.all(Array.from({ length: 20 }, () => f.service.evaluate(f.scope)));
  let rows = await f.store.listIncidents(f.scope, { limit: 100 });
  expect(rows).toHaveLength(1);
  expect(rows[0]?.ruleId).toBe(rule.id);
  expect(await f.store.listAlertNotifications(f.scope)).toHaveLength(1);
  f.advance(240000);
  await f.service.evaluate(f.scope);
  expect((await f.store.findIncident(f.scope.orgId, rows[0]!.id))?.state).toBe('open');
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  rows = await f.store.listIncidents(f.scope, { limit: 100 });
  expect(rows[0]?.state).toBe('resolved');
  expect(await f.store.listAlertNotifications(f.scope)).toHaveLength(2);
  expect(
    (await f.audit.list()).filter((r) => r.action === 'operations.incident.opened'),
  ).toHaveLength(1);
});
it('maintenance suppresses intents without hiding breaches; configuration requires current authority/session/version', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  await f.service.configure(p, f.scope, rule.id, {
    expectedVersion: rule.version,
    enabled: true,
    maintenanceUntil: new Date(+f.now() + 3600000),
    reason: 'maintenance',
  });
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toHaveLength(1);
  expect(await f.store.listAlertNotifications(f.scope)).toEqual([]);
  f.authority.authorize.mockRejectedValueOnce(new Error('denied'));
  await expect(f.service.create(p, f.scope, f.input)).rejects.toThrow('denied');
  f.authority.sessionActive.mockResolvedValue(false);
  await expect(f.service.list(p, f.scope)).rejects.toMatchObject({ code: 'unauthenticated' });
});
it('fences notification acknowledgements and retries outages without duplicate incident transitions', async () => {
  const f = await setup();
  await f.service.create(p, f.scope, f.input);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  f.deliver.mockRejectedValueOnce(new Error('private provider details'));
  await f.service.deliverPending(f.scope);
  let notes = await f.store.listAlertNotifications(f.scope);
  expect(notes[0]?.state).toBe('pending');
  expect(notes[0]?.attempts).toBe(1);
  f.advance(300000);
  await Promise.all([f.service.deliverPending(f.scope), f.service.deliverPending(f.scope)]);
  notes = await f.store.listAlertNotifications(f.scope);
  expect(notes[0]?.state).toBe('delivered');
  expect(f.deliver).toHaveBeenCalledTimes(2);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toHaveLength(1);
});

it('rolls back incident, intent and evaluation state when audit persistence fails', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  vi.spyOn(f.audit, 'appendMany').mockRejectedValueOnce(new Error('audit unavailable'));
  await expect(f.service.evaluate(f.scope)).rejects.toThrow('audit unavailable');
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toEqual([]);
  expect(await f.store.listAlertNotifications(f.scope)).toEqual([]);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.incidentId).toBeNull();
  await f.service.evaluate(f.scope);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toHaveLength(1);
});
it('uses scoped receipt-time counts, not occurrence time or another environment, and survives service restart', async () => {
  const f = await setup();
  const issued = await f.issue();
  await f.service.create(p, f.scope, {
    ...f.input,
    kind: 'event_count',
    eventType: 'conversion.failed',
    threshold: 2,
  });
  const { randomUUID } = await import('node:crypto');
  const event = (id: string) => ({
    ...f.scope,
    id,
    componentId: f.componentId,
    credentialId: issued.credential.id,
    source: 'backend_report' as const,
    type: 'conversion.failed',
    attributes: { reason: 'timeout' },
    occurredAt: new Date(+f.now() - 86400000).toISOString(),
    receivedAt: new Date(+f.now() + 1),
    expiresAt: new Date(+f.now() + 30 * 86400000),
    contentHash: 'a'.repeat(64),
    sizeBytes: 600,
  });
  await f.store.transaction(f.scope.orgId, async (tx) => {
    await tx.insertEvent(event(randomUUID()));
    await tx.insertEvent(event(randomUUID()));
  });
  f.advance(2);
  await f.service.evaluate(f.scope);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toHaveLength(1);
  expect(
    await f.store.countAlertEvents(
      { ...f.scope, environmentId: 'ope_' + 'f'.repeat(24) },
      f.componentId,
      'conversion.failed',
      f.now(),
      new Date(+f.now() + 10),
      5,
    ),
  ).toBe(0);
  const restarted = new AutomationService({
    store: f.store,
    clock: { now: () => new Date(+f.now() + 2) },
    enabled: () => true,
    authority: f.authority,
  });
  await restarted.evaluate(f.scope);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toHaveLength(1);
});

it('rejects a late acknowledgement after another worker reclaims the lease and expires undeliverable intents', async () => {
  const f = await setup();
  await f.service.create(p, f.scope, f.input);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  let release!: () => void;
  let entered!: () => void;
  const began = new Promise<void>((r) => {
    entered = r;
  });
  f.deliver.mockImplementationOnce(
    () =>
      new Promise<void>((r) => {
        release = r;
        entered();
      }),
  );
  const first = f.service.deliverPending(f.scope);
  await began;
  f.advance(31000);
  let releaseSecond!: () => void;
  let enteredSecond!: () => void;
  const secondBegan = new Promise<void>((r) => {
    enteredSecond = r;
  });
  const second = new AutomationService({
    store: f.store,
    clock: { now: () => new Date(+f.now() + 91000) },
    enabled: () => true,
    authority: f.authority,
    deliver: () =>
      new Promise<void>((r) => {
        releaseSecond = r;
        enteredSecond();
      }),
  });
  const secondPending = second.deliverPending(f.scope);
  await secondBegan;
  release();
  await first;
  expect((await f.store.listAlertNotifications(f.scope))[0]?.state).toBe('claimed');
  releaseSecond();
  await secondPending;
  const notes = await f.store.listAlertNotifications(f.scope);
  expect(notes[0]?.state).toBe('delivered');
  expect(notes[0]?.attempts).toBe(2);
});
it('keeps failures visible after the 72-hour deadline and withholds notifications from inactive members', async () => {
  const f = await setup();
  await f.service.create(p, f.scope, f.input);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  f.advance(73 * 3600000);
  await f.service.deliverPending(f.scope);
  expect((await f.store.listAlertNotifications(f.scope))[0]?.state).toBe('failed');
  expect(f.deliver).not.toHaveBeenCalled();
  const publicRows = await f.service.notifications(p, f.scope);
  expect(publicRows.items[0]).not.toHaveProperty('claimToken');
});

it('honors disabled rules, write freezes, inactive recipients and finite typed budgets', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  f.authority.assertWritable.mockRejectedValueOnce(new Error('frozen'));
  await expect(
    f.service.configure(p, f.scope, rule.id, {
      expectedVersion: rule.version,
      enabled: false,
      maintenanceUntil: null,
      reason: 'security_response',
    }),
  ).rejects.toThrow('frozen');
  await f.service.configure(p, f.scope, rule.id, {
    expectedVersion: rule.version,
    enabled: false,
    maintenanceUntil: null,
    reason: 'security_response',
  });
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toEqual([]);
  for (const change of [
    { kind: 'event_count', eventType: 'conversion.failed', threshold: 0 },
    { windowSeconds: 3601 },
    { kind: 'heartbeat', eventType: 'conversion.failed' },
    { runbook: 'https://private.invalid' },
  ])
    await expect(
      f.service.create(p, f.scope, { ...f.input, ...change } as typeof f.input),
    ).rejects.toMatchObject({ code: 'invalid_request' });
  const second = await f.service.create(p, f.scope, f.input);
  f.authority.activeMember.mockResolvedValue(false);
  await f.heartbeat('unavailable');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, second.id))?.observation).toBe('breaching');
  expect(await f.store.listAlertNotifications(f.scope)).toEqual([]);
});
it('does not trust a heartbeat equal to the timestamp of a changed inventory epoch', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  await f.heartbeat('healthy');
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const c = (await tx.find('component', f.scope.orgId, f.componentId))!;
    await tx.update('component', { ...c, version: 2, updatedAt: f.now() }, 1);
  });
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation).toBe('unknown');
});

it('keeps the domain disabled even without an HTTP gate', async () => {
  const f = await setup();
  const off = new AutomationService({
    store: f.store,
    clock: { now: f.now },
    authority: f.authority,
    enabled: () => false,
  });
  await expect(off.create(p, f.scope, f.input)).rejects.toMatchObject({ code: 'not_found' });
  await expect(off.list(p, f.scope)).rejects.toMatchObject({ code: 'not_found' });
  await off.tick();
  expect(await f.store.listAlertRules(f.scope)).toEqual([]);
});
it('opens an incident when a component that reported healthy goes silent, and recovers on fresh reports', async () => {
  // A crashed or unreachable source sends nothing at all: its last report must age into a breach,
  // not remain "unknown" (the Rokela PDF outages of 24 October 2026 sent no heartbeat).
  const f = await setup();
  const rule = await f.service.create(p, f.scope, f.input);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation).toBe('healthy');
  f.advance(179000);
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation).toBe('healthy');
  f.advance(1000);
  await f.service.evaluate(f.scope);
  expect((await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation).toBe('breaching');
  expect(await f.store.listIncidents(f.scope, { limit: 100 })).toEqual([]);
  f.advance(60000);
  await f.service.evaluate(f.scope);
  const [incident] = await f.store.listIncidents(f.scope, { limit: 100 });
  expect(incident?.state).toBe('open');
  expect(incident?.ruleId).toBe(rule.id);
  expect((await f.store.listAlertNotifications(f.scope)).map((n) => n.transition)).toEqual([
    'opened',
  ]);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  expect((await f.store.findIncident(f.scope.orgId, incident!.id))?.state).toBe('resolved');
});
it('evaluates probe rules only on Warrior probe results, never on backend reports', async () => {
  const f = await setup();
  const rule = await f.service.create(p, f.scope, { ...f.input, kind: 'probe' });
  const probe = f.probe;
  const observation = async () =>
    (await f.store.findAlertRule(f.scope.orgId, rule.id))?.observation;
  // A healthy backend report says nothing about what Warrior can reach from outside.
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  expect(await observation()).toBe('unknown');
  // A failing probe breaches even while the backend keeps reporting healthy.
  await probe('unavailable');
  await f.service.evaluate(f.scope);
  expect(await observation()).toBe('breaching');
  f.advance(60000);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  const [incident] = await f.store.listIncidents(f.scope, { limit: 100 });
  expect(incident).toMatchObject({ state: 'open', ruleId: rule.id });
  await probe('healthy');
  await f.service.evaluate(f.scope);
  f.advance(60000);
  await probe('healthy');
  await f.service.evaluate(f.scope);
  expect((await f.store.findIncident(f.scope.orgId, incident!.id))?.state).toBe('resolved');
  // Probes that stop arriving breach like silent heartbeats.
  f.advance(180000);
  await f.heartbeat('healthy');
  await f.service.evaluate(f.scope);
  expect(await observation()).toBe('breaching');
});
