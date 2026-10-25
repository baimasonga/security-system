import { expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { computeAnchor, createAnchor, InMemoryAuditLog, type AnchorManifest } from '@trust/audit';
import { createWitnessReceiver } from '../../../tools/audit-witness/receiver.ts';
import { createLockedStore, type ObjectFacts } from '../../../tools/audit-witness/locked-store.ts';

const token = 'a'.repeat(32);
const chains = [{ chain: 'system', seq: 1, hash: 'b'.repeat(64) }];
const manifest = {
  v: 1,
  created_at: '2026-10-24T12:00:00.000Z',
  anchor: computeAnchor(chains),
  chains,
};
const request = (body = JSON.stringify(manifest)) => ({
  method: 'POST',
  path: '/anchors',
  authorization: `Bearer ${token}`,
  contentType: 'application/json',
  body,
});
it.each(['', 'short', 'a'.repeat(257), 'a'.repeat(32) + '\n'])(
  'rejects invalid token configuration',
  (bad) => {
    expect(() =>
      createWitnessReceiver({ token: bad, store: { retain: async () => 'receipt' } }),
    ).toThrow();
  },
);
it('rejects unsafe sequences even when the shared digest is valid', async () => {
  const bad = [{ ...chains[0]!, seq: Number.MAX_SAFE_INTEGER + 1 }];
  const retain = vi.fn();
  const r = await createWitnessReceiver({ token, store: { retain } })(
    request(JSON.stringify({ ...manifest, chains: bad, anchor: computeAnchor(bad) })),
  );
  expect(r.statusCode).toBe(400);
  expect(retain).not.toHaveBeenCalled();
});
it('bounds chain count independently of body size', async () => {
  const many = Array.from({ length: 5001 }, (_, n) => ({ ...chains[0]!, chain: `org:org_${n}` }));
  const r = await createWitnessReceiver({ token, store: { retain: async () => 'receipt' } })(
    request(JSON.stringify({ ...manifest, chains: many, anchor: computeAnchor(many) })),
  );
  expect(r.statusCode).toBe(400);
});
it('retains earlier evidence across later manifests and detects tampered synthetic history', async () => {
  const now = () => new Date('2026-10-24T12:00:00Z');
  const log = new InMemoryAuditLog({ now }, { shards: 4 });
  const objects = new Map<string, { body: string; facts: ObjectFacts }>();
  const store = createLockedStore(
    {
      put: async (key, body, digest, until) => {
        if (objects.has(key)) return undefined;
        const version = `v${objects.size + 1}`;
        objects.set(key, {
          body,
          facts: { version, digest, mode: 'COMPLIANCE', retainUntil: until },
        });
        return version;
      },
      head: async (key) => objects.get(key)?.facts,
    },
    365,
    now,
  );
  const receive = createWitnessReceiver({ token, store });
  await log.append({ actor: { type: 'system' }, action: 'synthetic.test', orgId: 'org_a' });
  const a = await createAnchor(log, now());
  if (!a.ok) throw new Error('fixture failure');
  expect((await receive(request(JSON.stringify(a.manifest)))).statusCode).toBe(201);
  await log.append({ actor: { type: 'system' }, action: 'synthetic.second', orgId: 'org_a' });
  const b = await createAnchor(log, now());
  if (!b.ok) throw new Error('fixture failure');
  expect((await receive(request(JSON.stringify(b.manifest)))).statusCode).toBe(201);
  expect(objects.size).toBe(2);
  const earlier = JSON.parse([...objects.values()][0]!.body) as AnchorManifest;
  expect((await log.checkAnchor(earlier)).ok).toBe(true);
  const event = (await log.list())[0]!;
  log.unsafeReplaceForTest(0, { ...event, hash: '0'.repeat(64) });
  expect((await log.checkAnchor(earlier)).ok).toBe(false);
});

it('acknowledges only after storage and returns a bounded receipt', async () => {
  const store = { retain: vi.fn(async (_body: string) => 'v1:receipt') };
  const r = await createWitnessReceiver({ token, store })(request());
  expect(r.statusCode).toBe(201);
  expect(r.headers['x-witness-receipt']).toBe('v1:receipt');
  expect(store.retain).toHaveBeenCalledOnce();
  expect(JSON.parse(store.retain.mock.calls[0]![0] as string)).toEqual(manifest);
});
it.each([
  { authorization: 'Bearer wrong' },
  { authorization: '' },
  { method: 'GET' },
  { path: '/other' },
  { contentType: 'text/plain' },
])('rejects unauthorized or unsupported requests before storage %j', async (change) => {
  const retain = vi.fn();
  const r = await createWitnessReceiver({ token, store: { retain } })({ ...request(), ...change });
  expect(r.statusCode).toBeGreaterThanOrEqual(400);
  expect(retain).not.toHaveBeenCalled();
});
it.each([
  'null',
  '{',
  JSON.stringify({ ...manifest, extra: 'SECRET' }),
  JSON.stringify({ ...manifest, created_at: 'invalid' }),
  JSON.stringify({ ...manifest, anchor: '0'.repeat(64) }),
  JSON.stringify({ ...manifest, chains: [...chains, ...chains] }),
  JSON.stringify({ ...manifest, chains: [{ ...chains[0], seq: Number.MAX_SAFE_INTEGER + 1 }] }),
  JSON.stringify({ ...manifest, chains: [{ ...chains[0], hash: 'not-a-hash' }] }),
  JSON.stringify(manifest) + ' '.repeat(1_000_000),
])('rejects malformed and excessive evidence without reflecting it', async (body) => {
  const retain = vi.fn();
  const r = await createWitnessReceiver({ token, store: { retain } })(request(body));
  expect(r.statusCode).toBeGreaterThanOrEqual(400);
  expect(JSON.stringify(r)).not.toContain('SECRET');
  expect(retain).not.toHaveBeenCalled();
});
it('fails closed on storage errors and invalid receipts', async () => {
  for (const retain of [
    async () => {
      throw new Error('SECRET');
    },
    async () => '',
    async () => '\r\nSECRET',
  ]) {
    const r = await createWitnessReceiver({ token, store: { retain } })(request());
    expect(r.statusCode).toBe(503);
    expect(JSON.stringify(r)).not.toContain('SECRET');
  }
});

function fixture() {
  let fact: ObjectFacts | undefined;
  const put = vi.fn(async (_key: string, _body: string, digest: string, until: Date) => {
    if (fact) return undefined;
    fact = { version: 'version-1', digest, mode: 'COMPLIANCE', retainUntil: until };
    return fact.version;
  });
  const head = vi.fn(async () => fact);
  const port = { put, head };
  const now = () => new Date('2026-10-24T12:00:00Z');
  return {
    port,
    now,
    set: (f: ObjectFacts) => {
      fact = f;
    },
  };
}
it('retains the full manifest and gives the same version receipt after receiver restart', async () => {
  const f = fixture();
  const body = JSON.stringify(manifest);
  const a = await createLockedStore(f.port, 365, f.now).retain(body);
  const b = await createLockedStore(f.port, 365, f.now).retain(body);
  expect(a).toBe(b);
  expect(a).toMatch(/^v1:[a-f0-9]{64}:[A-Za-z0-9_-]+$/);
  expect(Buffer.from(a.split(':')[2]!, 'base64url').toString()).toBe('version-1');
  expect(f.port.put).toHaveBeenCalledTimes(2);
  expect(f.port.put.mock.calls[0]![1]).toBe(body);
});
it('accepts sharded audit identifiers used by the shared audit package', async () => {
  const sharded = [{ ...chains[0]!, chain: 'org:org_123#3' }];
  const body = JSON.stringify({ ...manifest, chains: sharded, anchor: computeAnchor(sharded) });
  const r = await createWitnessReceiver({ token, store: { retain: async () => 'receipt' } })(
    request(body),
  );
  expect(r.statusCode).toBe(201);
});
it('concurrent retries converge and encode opaque S3 version IDs safely', async () => {
  const f = fixture();
  const store = createLockedStore(f.port, 365, f.now);
  await store.retain(JSON.stringify(manifest));
  f.set({ ...(await f.port.head())!, version: '3/L4kqt+opaque=' });
  const receipts = await Promise.all(
    Array.from({ length: 10 }, () => store.retain(JSON.stringify(manifest))),
  );
  expect(new Set(receipts).size).toBe(1);
  expect(Buffer.from(receipts[0]!.split(':')[2]!, 'base64url').toString()).toBe('3/L4kqt+opaque=');
});
it('rejects a new write whose retention deadline or returned version does not match', async () => {
  for (const facts of [
    { version: 'other', retainUntil: new Date('2030-01-01') },
    { version: 'v1', retainUntil: new Date('2026-10-25') },
  ]) {
    const port = {
      put: async () => 'v1',
      head: async () => ({
        ...facts,
        digest: createHash('sha256').update('body').digest('hex'),
        mode: 'COMPLIANCE',
      }),
    };
    await expect(
      createLockedStore(port, 365, () => new Date('2026-10-24')).retain('body'),
    ).rejects.toThrow();
  }
});
it.each(['GOVERNANCE', 'NONE'])('rejects non-compliance storage %s', async (mode) => {
  const f = fixture();
  const store = createLockedStore(f.port, 365, f.now);
  await store.retain(JSON.stringify(manifest));
  const facts = (await f.port.head())!;
  f.set({ ...facts, mode });
  await expect(store.retain(JSON.stringify(manifest))).rejects.toThrow();
});
it('rejects expired retention, digest mismatch and missing version', async () => {
  for (const change of [{ retainUntil: new Date(0) }, { digest: 'wrong' }, { version: '' }]) {
    const f = fixture();
    const store = createLockedStore(f.port, 365, f.now);
    await store.retain(JSON.stringify(manifest));
    f.set({ ...(await f.port.head())!, ...change });
    await expect(store.retain(JSON.stringify(manifest))).rejects.toThrow();
  }
});
