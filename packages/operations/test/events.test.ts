import { eventIngestionContract, eventRevokeRaceContract } from './event-ingestion-contract.ts';
import { eventFixture } from './event-fixture.ts';
import { eventStoreContract } from './event-store-contract.ts';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { validateEventBatch } from '../src/index.ts';
it('rejects scope overrides and private attributes before storage', () => {
  expect(() => validateEventBatch({ schema: 1, events: [], org_id: 'secret' })).toThrow();
  expect(() =>
    validateEventBatch({
      schema: 1,
      events: [
        {
          id: '00000000-0000-4000-8000-000000000001',
          component_id: 'opm_' + 'a'.repeat(24),
          occurred_at: '2026-10-19T00:00:00Z',
          type: 'component.heartbeat',
          attributes: { status: 'healthy', filename: 'private.pdf' },
        },
      ],
    }),
  ).toThrow();
});
it('accepts a typed content-free heartbeat batch', () => {
  const event = {
    id: '00000000-0000-4000-8000-000000000001',
    component_id: 'opm_' + 'a'.repeat(24),
    occurred_at: '2026-10-19T00:00:00Z',
    type: 'component.heartbeat',
    attributes: { status: 'healthy' },
  };
  expect(validateEventBatch({ schema: 1, events: [event] })).toEqual([event]);
});

eventStoreContract(async () => {
  const f = await eventFixture();
  // Contract fixtures use a fixed public credential ID; no real secret is involved.
  await f.store.transaction(f.scope.orgId, (tx) =>
    tx.insertCredential({
      ...f.scope,
      id: 'opc_' + 'a'.repeat(32),
      purpose: 'events:write',
      source: 'backend_report',
      secretHash: 'b'.repeat(64),
      createdAt: f.now(),
      expiresAt: new Date(+f.now() + 86400000),
      revokedAt: null,
      rotatedAt: null,
    }),
  );
  return f;
});
const heartbeat = (component: string, time: Date, id = '00000000-0000-4000-8000-000000000001') => ({
  id,
  component_id: component,
  occurred_at: time.toISOString(),
  type: 'component.heartbeat',
  attributes: { status: 'healthy' },
});
it('validates all nine safe event variants and rejects raw content and invalid dates', () => {
  const examples = JSON.parse(
    readFileSync(
      new URL('../../../docs/api/operations-safe-examples.json', import.meta.url),
      'utf8',
    ),
  );
  expect(validateEventBatch(examples)).toHaveLength(9);
  const valid = heartbeat('opm_' + 'a'.repeat(24), new Date('2026-10-19T00:00:00Z'));
  for (const change of [
    { occurred_at: '2026-02-30T00:00:00Z' },
    { occurred_at: '2026-10-19T00:00:00+00:00' },
    { severity: 'critical' },
    { attributes: { status: 'person@example.test' } },
    { attributes: { status: 'healthy', password: 'do-not-store' } },
    { type: 'browser.event' },
  ])
    expect(() => validateEventBatch({ schema: 1, events: [{ ...valid, ...change }] })).toThrow();
});
it('deduplicates canonical retries across rotation before freshness and charges only new events', async () => {
  const f = await eventFixture();
  const token = (await f.issue()).token;
  const event = heartbeat(f.componentId, f.now());
  const first = await f.events.ingest(token, { schema: 1, events: [event, event] });
  expect(first.accepted).toEqual([
    { id: event.id, disposition: 'stored', received_at: f.now().toISOString() },
  ]);
  const stored = await f.store.findEvent(f.scope, event.id);
  expect(stored).toMatchObject({
    source: 'backend_report',
    orgId: f.scope.orgId,
    credentialId: token.split('.')[1],
  });
  const originalBudget = await f.store.getEventCounter(f.scope.orgId, 'storage:org');
  f.advance(2 * 86400000);
  const second = (
    await f.service.rotate(
      {
        kind: 'user',
        userId: 'usr_' + 'a'.repeat(24),
        sessionId: 'test-session',
        platformRole: 'none',
      },
      f.scope,
      token.split('.')[1]!,
      { ...f.input, ttlSeconds: 7776000, overlapSeconds: 0 },
    )
  ).token;
  const retry = await f.events.ingest(second, {
    schema: 1,
    events: [{ ...event, attributes: { status: 'healthy' } }],
  });
  expect(retry.accepted).toEqual([{ ...first.accepted[0], disposition: 'duplicate' }]);
  expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toEqual(originalBudget);
  await expect(
    f.events.ingest(second, {
      schema: 1,
      events: [{ ...event, attributes: { status: 'degraded' } }],
    }),
  ).rejects.toMatchObject({ code: 'conflict' });
});
it('rejects a mixed stale/conflicting/out-of-scope batch without partial writes or budget charges', async () => {
  const f = await eventFixture();
  const token = (await f.issue()).token;
  const a = heartbeat(f.componentId, f.now());
  const b = heartbeat(
    f.componentId,
    new Date(+f.now() - 86400001),
    '00000000-0000-4000-8000-000000000002',
  );
  await expect(f.events.ingest(token, { schema: 1, events: [a, b] })).rejects.toMatchObject({
    code: 'unprocessable',
  });
  expect(await f.store.findEvent(f.scope, a.id)).toBeUndefined();
  expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toBeUndefined();
  await expect(
    f.events.ingest(token, {
      schema: 1,
      events: [
        a,
        { ...b, occurred_at: f.now().toISOString(), component_id: 'opm_' + 'f'.repeat(24) },
      ],
    }),
  ).rejects.toMatchObject({ code: 'not_found' });
  expect(await f.store.findEvent(f.scope, a.id)).toBeUndefined();
  await expect(
    f.events.ingest(token, { schema: 1, events: [a, { ...a, attributes: { status: 'unknown' } }] }),
  ).rejects.toMatchObject({ code: 'conflict' });
});
it('enforces sliding request, UTC daily and storage budgets atomically, including duplicate retries', async () => {
  const f = await eventFixture();
  const token = (await f.issue()).token;
  const event = heartbeat(f.componentId, f.now());
  for (let i = 0; i < 60; i++) await f.events.ingest(token, { schema: 1, events: [event] });
  await expect(f.events.ingest(token, { schema: 1, events: [event] })).rejects.toMatchObject({
    code: 'rate_limited',
  });
  expect((await f.store.getEventCounter(f.scope.orgId, 'storage:org'))?.count).toBe(1);
  f.advance(60000);
  await f.events.ingest(token, { schema: 1, events: [event] });
  for (const [key, count, bytes] of [
    [`day:env:${f.scope.environmentId}:2026-10-19`, 10000, 0],
    ['day:org:2026-10-19', 100000, 0],
    ['storage:org', 1, 2 * 1024 ** 3],
    [`storage:env:${f.scope.environmentId}`, 1, 500 * 1024 ** 2],
  ] as const) {
    const before = await f.store.getEventCounter(f.scope.orgId, key);
    await f.store.transaction(f.scope.orgId, (tx) =>
      tx.putEventCounter({
        orgId: f.scope.orgId,
        key,
        count,
        bytes,
        requestTimes: [],
        expiresAt: null,
      }),
    );
    const another = heartbeat(f.componentId, f.now(), '00000000-0000-4000-8000-000000000002');
    await expect(f.events.ingest(token, { schema: 1, events: [another] })).rejects.toMatchObject({
      code: 'rate_limited',
    });
    expect(await f.store.findEvent(f.scope, another.id)).toBeUndefined();
    await f.store.transaction(f.scope.orgId, (tx) => tx.putEventCounter(before!));
  }
});
it('retains receipt identities thirty days, releases bytes atomically and expires hourly aggregates at ninety days', async () => {
  const f = await eventFixture();
  const token = (await f.issue()).token;
  const event = heartbeat(f.componentId, f.now());
  await f.events.ingest(token, { schema: 1, events: [event] });
  const hour = f.now();
  expect(
    (await f.store.getEventAggregate(f.scope, f.componentId, event.type, hour, 'healthy'))?.count,
  ).toBe(1);
  f.advance(30 * 86400000 - 1);
  expect(await f.events.retain()).toBe(0);
  f.advance(1);
  expect(await f.events.retain()).toBe(1);
  expect(await f.events.retain()).toBe(0);
  expect(await f.store.findEvent(f.scope, event.id)).toBeUndefined();
  expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toMatchObject({
    count: 0,
    bytes: 0,
  });
  expect(
    await f.store.getEventAggregate(f.scope, f.componentId, event.type, hour, 'healthy'),
  ).toBeDefined();
  f.advance(60 * 86400000);
  await f.events.retain();
  expect(
    await f.store.getEventAggregate(f.scope, f.componentId, event.type, hour, 'healthy'),
  ).toBeUndefined();
});

eventIngestionContract(async () => {
  const f = await eventFixture();
  return { ...f, token: (await f.issue()).token };
});

it('bounds each retention deletion to one thousand rows and releases exact remaining storage', async () => {
  const f = await eventFixture();
  const token = (await f.issue()).token;
  for (let start = 1; start <= 1001; start += 100) {
    const events = Array.from({ length: Math.min(100, 1002 - start) }, (_, offset) =>
      heartbeat(
        f.componentId,
        f.now(),
        `00000000-0000-4000-8000-${(start + offset).toString(16).padStart(12, '0')}`,
      ),
    );
    await f.events.ingest(token, { schema: 1, events });
  }
  const initial = (await f.store.getEventCounter(f.scope.orgId, 'storage:org'))!;
  expect(initial.count).toBe(1001);
  f.advance(30 * 86400000);
  expect(await f.events.retain()).toBe(1000);
  const remaining = (await f.store.getEventCounter(f.scope.orgId, 'storage:org'))!;
  expect(remaining.count).toBe(1);
  expect(remaining.bytes).toBe(initial.bytes / 1001);
  expect(await f.events.retain()).toBe(1);
  expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toMatchObject({
    count: 0,
    bytes: 0,
  });
});
it('keeps outcome aggregates separate and enforces inclusive occurrence clock bounds', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token;
  const healthy = heartbeat(f.componentId, new Date(+f.now() - 86400000));
  const unavailable = {
    ...heartbeat(
      f.componentId,
      new Date(+f.now() + 300000),
      '00000000-0000-4000-8000-000000000002',
    ),
    attributes: { status: 'unavailable' },
  };
  await f.events.ingest(token, { schema: 1, events: [healthy, unavailable] });
  expect(
    (await f.store.getEventAggregate(f.scope, f.componentId, healthy.type, f.now(), 'healthy'))
      ?.count,
  ).toBe(1);
  expect(
    (await f.store.getEventAggregate(f.scope, f.componentId, healthy.type, f.now(), 'unavailable'))
      ?.count,
  ).toBe(1);
  for (const occurred_at of [
    new Date(+f.now() - 86400001).toISOString(),
    new Date(+f.now() + 300001).toISOString(),
  ])
    await expect(
      f.events.ingest(token, {
        schema: 1,
        events: [{ ...healthy, id: '00000000-0000-4000-8000-000000000003', occurred_at }],
      }),
    ).rejects.toMatchObject({ code: 'unprocessable' });
});

eventRevokeRaceContract(async () => {
  const f = await eventFixture();
  return { ...f, token: (await f.issue()).token };
});
it('refuses new observations from a disabled component without deleting history', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token;
  const first = heartbeat(f.componentId, f.now());
  await f.events.ingest(token, { schema: 1, events: [first] });
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const row = await tx.find('component', f.scope.orgId, f.componentId);
    await tx.update('component', { ...row!, state: 'disabled', version: 2 }, 1);
  });
  const second = { ...first, id: '00000000-0000-4000-8000-000000000002' };
  await expect(f.events.ingest(token, { schema: 1, events: [second] })).rejects.toMatchObject({
    code: 'unprocessable',
  });
  expect(await f.store.findEvent(f.scope, first.id)).toBeDefined();
  expect(await f.store.findEvent(f.scope, second.id)).toBeUndefined();
});
it('deduplicates reordered attributes but conflicts on a changed timestamp spelling', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token;
  const input = {
    ...heartbeat(f.componentId, f.now()),
    type: 'conversion.failed',
    attributes: { source_type: 'pdf', target_type: 'image', reason: 'timeout', duration_ms: 5 },
  };
  await f.events.ingest(token, { schema: 1, events: [input] });
  const reordered = {
    ...input,
    attributes: Object.fromEntries(Object.entries(input.attributes).reverse()),
  };
  await expect(f.events.ingest(token, { schema: 1, events: [reordered] })).resolves.toMatchObject({
    accepted: [{ disposition: 'duplicate' }],
  });
  await expect(
    f.events.ingest(token, {
      schema: 1,
      events: [{ ...input, occurred_at: input.occurred_at.replace('.000Z', 'Z') }],
    }),
  ).rejects.toMatchObject({ code: 'conflict' });
});
it('enforces runtime numeric bounds and enums for each safe event variant', () => {
  const examples = JSON.parse(
    readFileSync(
      new URL('../../../docs/api/operations-safe-examples.json', import.meta.url),
      'utf8',
    ),
  );
  for (const event of examples.events)
    for (const [key, value] of Object.entries(event.attributes))
      if (typeof value === 'number')
        for (const bad of [-1, 1.5, 1000000000])
          expect(() =>
            validateEventBatch({
              schema: 1,
              events: [{ ...event, attributes: { ...event.attributes, [key]: bad } }],
            }),
          ).toThrow();
  expect(() =>
    validateEventBatch({
      schema: 1,
      events: [
        {
          ...heartbeat('opm_' + 'a'.repeat(24), new Date('2026-10-19T00:00:00Z')),
          attributes: { status: 'panic' },
        },
      ],
    }),
  ).toThrow();
});
it('refuses a real component from a different environment in the same organization', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token;
  const environmentId = 'ope_' + 'b'.repeat(24),
    componentId = 'opm_' + 'b'.repeat(24);
  await f.store.transaction(f.scope.orgId, async (tx) => {
    const parent = await tx.find('environment', f.scope.orgId, f.scope.environmentId);
    await tx.insert('environment', {
      ...parent!,
      id: environmentId,
      code: 'production',
      kind: 'production',
    });
    await tx.insert('component', {
      ...f.scope,
      environmentId,
      id: componentId,
      code: 'worker',
      state: 'active',
      version: 1,
      createdAt: f.now(),
      updatedAt: f.now(),
      kind: 'worker',
      dependencyIds: [],
    });
  });
  const input = heartbeat(componentId, f.now());
  await expect(f.events.ingest(token, { schema: 1, events: [input] })).rejects.toMatchObject({
    code: 'not_found',
  });
  expect(await f.store.findEvent(f.scope, input.id)).toBeUndefined();
});
it('enforces the byte cap below the HTTP layer too', () => {
  const input = {
    ...heartbeat('opm_' + 'a'.repeat(24), new Date('2026-10-19T00:00:00Z')),
    occurred_at: '2026-10-19T00:00:00.' + '1'.repeat(262144) + 'Z',
  };
  expect(() => validateEventBatch({ schema: 1, events: [input] })).toThrowError(
    expect.objectContaining({ code: 'too_large' }),
  );
});
it('meters authenticated schema refusals without storing their payloads', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token;
  for (let i = 0; i < 60; i++)
    await expect(f.events.ingest(token, { schema: 2, events: [] })).rejects.toMatchObject({
      code: 'unprocessable',
    });
  expect(
    (await f.store.getEventCounter(f.scope.orgId, 'request:' + token.split('.')[1]))?.requestTimes,
  ).toHaveLength(60);
  expect(await f.store.getEventCounter(f.scope.orgId, 'storage:org')).toBeUndefined();
  await expect(
    f.events.ingest(token, { schema: 1, events: [heartbeat(f.componentId, f.now())] }),
  ).rejects.toMatchObject({ code: 'rate_limited' });
});

it('charges rejected conflicts once while preserving event and storage identity', async () => {
  const f = await eventFixture(),
    token = (await f.issue()).token,
    first = heartbeat(f.componentId, f.now());
  await f.events.ingest(token, { schema: 1, events: [first] });
  await expect(
    f.events.ingest(token, {
      schema: 1,
      events: [{ ...first, attributes: { status: 'degraded' } }],
    }),
  ).rejects.toMatchObject({ code: 'conflict' });
  expect(
    (await f.store.getEventCounter(f.scope.orgId, 'request:' + token.split('.')[1]))?.requestTimes,
  ).toHaveLength(2);
  expect((await f.store.getEventCounter(f.scope.orgId, 'storage:org'))?.count).toBe(1);
});
