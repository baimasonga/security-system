import { expect, it, vi } from 'vitest';
import { PostureService, InMemoryInventoryStore } from '../src/index.ts';
import { postureStoreContract } from './posture-store-contract.ts';
import { eventFixture } from './event-fixture.ts';
postureStoreContract(async () => new InMemoryInventoryStore());
const p = {
  kind: 'user' as const,
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'session',
  platformRole: 'none' as const,
};
async function fixture() {
  const f = await eventFixture();
  const authority = {
    authorize: vi.fn(async () => {}),
    assertWritable: vi.fn(async () => {}),
    activeMember: vi.fn(async () => true),
    activeProduct: vi.fn(async () => true),
    sessionActive: vi.fn(async () => true),
  };
  const input = {
    component_id: f.componentId,
    source: 'github_dependabot',
    revision: 'a'.repeat(40),
    run_id: '1',
    completed_at: f.now().toISOString(),
    outcome: 'completed',
    findings: [
      { fingerprint: 'b'.repeat(64), severity: 'critical', advisory_id: 'CVE-2026-12345' },
    ],
    reason: 'initial_setup',
  };
  const service = new PostureService({
    store: f.store,
    clock: { now: f.now },
    authority,
    enabled: () => true,
  });
  return { ...f, authority, input, service };
}
it('rechecks live authority inside the transaction and refuses revoked sessions and freeze', async () => {
  const f = await fixture();
  f.authority.authorize
    .mockResolvedValueOnce()
    .mockRejectedValueOnce(new Error('membership removed'));
  await expect(f.service.importScan(p, f.scope, f.input)).rejects.toThrow('membership removed');
  expect(await f.store.listSecurityEvidence(f.scope, 'scan', 100)).toEqual([]);
  f.authority.authorize.mockResolvedValue();
  f.authority.sessionActive.mockResolvedValue(false);
  await expect(f.service.read(p, f.scope)).rejects.toMatchObject({ code: 'unauthenticated' });
  f.authority.sessionActive.mockResolvedValue(true);
  f.authority.assertWritable.mockRejectedValue(new Error('frozen'));
  await expect(f.service.importScan(p, f.scope, f.input)).rejects.toThrow('frozen');
  await expect(f.service.read(p, f.scope)).resolves.toHaveProperty('scans');
});
it('rolls back evidence and findings if audit fails; successful retries preserve snapshot identity', async () => {
  const f = await fixture();
  const failing = new PostureService({
    store: {
      ...f.store,
      transaction: (org, fn) =>
        f.store.transaction(org, (tx) =>
          fn(
            new Proxy(tx, {
              get(target, key) {
                if (key === 'audit')
                  return {
                    append: async () => {
                      throw new Error('audit failed');
                    },
                  };
                const value = Reflect.get(target, key);
                return typeof value === 'function' ? value.bind(target) : value;
              },
            }),
          ),
        ),
    } as typeof f.store,
    clock: { now: f.now },
    authority: f.authority,
    enabled: () => true,
  });
  await expect(failing.importScan(p, f.scope, f.input)).rejects.toThrow('audit failed');
  expect(await f.store.listSecurityEvidence(f.scope, 'scan', 100)).toEqual([]);
  expect(await f.store.listSecurityFindings(f.scope, 100)).toEqual([]);
  const rows = await Promise.all(
    Array.from({ length: 20 }, () => f.service.importScan(p, f.scope, f.input)),
  );
  expect(rows.filter((r) => r.created)).toHaveLength(1);
  expect(new Set(rows.map((r) => r.id)).size).toBe(1);
});
it('bounds reports/findings and prioritizes unresolved critical findings without changing old snapshots', async () => {
  const f = await fixture();
  for (let i = 0; i < 100; i++)
    await f.service.importScan(p, f.scope, {
      ...f.input,
      run_id: String(i + 1),
      findings: i === 0 ? f.input.findings : [],
    });
  await expect(
    f.service.importScan(p, f.scope, { ...f.input, run_id: '101' }),
  ).rejects.toMatchObject({ code: 'quota_exceeded' });
  const view = await f.service.read(p, f.scope);
  expect(view.scans.items).toHaveLength(25);
  expect(view.scans.truncated).toBe(true);
  expect(view.findings.items[0]!.severity).toBe('critical');
  const first = view.findings.items[0]!;
  await f.service.configureFinding(p, f.scope, first.id, {
    expected_version: 1,
    state: 'resolved',
    assignee_user_id: p.userId,
    reason: 'security_response',
  });
  expect((await f.service.read(p, f.scope)).scans.items.some((s) => s.independentlyVerified)).toBe(
    false,
  );
});
