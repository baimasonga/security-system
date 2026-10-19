import { describe, expect, it, vi } from 'vitest';
import { InMemoryAuditLog } from '@trust/audit';
import { DomainError, type UserPrincipal } from '@trust/shared-types';
import { CredentialService, InMemoryInventoryStore, type CredentialScope } from '../src/index.ts';
import { application } from './store-contract.ts';
const principal: UserPrincipal = {
  kind: 'user',
  userId: 'usr_' + 'a'.repeat(24),
  sessionId: 'test-session',
  platformRole: 'none',
};
const DAY = 86400000;
async function fixture() {
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
    ttlSeconds: 86400,
    reason: 'initial_setup' as const,
    mfaCode: '123456',
  };
  const issue = () => service.issue(principal, scope, input);
  const valid = (
    token: string,
    expected: Partial<CredentialScope> & { purpose?: string; source?: string } = {},
  ) => service.withCredential(token, expected, async (_tx, identity) => identity);
  return {
    store,
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
describe('OPS-003 credential lifecycle and verification', () => {
  it('returns independent one-time tokens, persists only digests, bounds issue count and metadata pagination', async () => {
    const f = await fixture();
    const one = await f.issue(),
      two = await f.issue();
    expect(one.token).toMatch(/^ops_v1\.opc_[a-f0-9]{32}\.[a-f0-9]{64}$/);
    expect(one.token).not.toBe(two.token);
    await expect(f.issue()).rejects.toMatchObject({ code: 'conflict' });
    const stored = await f.store.findCredential(one.credential.id);
    expect(stored?.secretHash).toHaveLength(64);
    expect(JSON.stringify(stored)).not.toContain(one.token.split('.')[2]);
    const first = await f.service.list(principal, f.scope, { limit: 1 });
    expect(first.items).toHaveLength(1);
    expect(first.nextCursor).toBeTypeOf('string');
    const second = await f.service.list(principal, f.scope, {
      limit: 1,
      cursor: first.nextCursor!,
    });
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);
    expect(second.nextCursor).toBeNull();
    const serialized = JSON.stringify([
      one.credential,
      first,
      second,
      await f.audit.list({ orgId: f.scope.orgId }),
    ]);
    for (const secret of [one.token, two.token, one.token.split('.')[2]!, stored!.secretHash])
      expect(serialized).not.toContain(secret);
    expect(serialized).not.toMatch(/secretHash|rotatedAt|123456/);
    await expect(
      f.service.list(
        principal,
        { ...f.scope, environmentId: 'ope_' + 'f'.repeat(24) },
        { cursor: first.nextCursor! },
      ),
    ).rejects.toMatchObject({ code: 'not_found' });
    await expect(f.service.list(principal, f.scope, { cursor: 'invalid' })).rejects.toMatchObject({
      code: 'invalid_request',
    });
  });
  it('requires permission, live session and step-up; never substitutes a license key or user session for credentials', async () => {
    const f = await fixture();
    f.deps.authorize.mockRejectedValueOnce(new DomainError('forbidden', 'test'));
    await expect(f.issue()).rejects.toMatchObject({ code: 'forbidden' });
    expect(f.deps.stepUp).not.toHaveBeenCalled();
    f.deps.sessionActive.mockResolvedValueOnce(false);
    await expect(f.issue()).rejects.toMatchObject({ code: 'unauthenticated' });
    f.deps.stepUp.mockRejectedValueOnce(new DomainError('unauthenticated', 'test'));
    await expect(f.issue()).rejects.toMatchObject({ code: 'unauthenticated' });
    expect((await f.service.list(principal, f.scope)).items).toEqual([]);
    for (const token of [
      'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
      'sess_abcd',
      'Bearer anything',
      undefined,
    ])
      await expect(f.service.withCredential(token, {}, async () => true)).rejects.toMatchObject({
        code: 'unauthenticated',
      });
  });
  it('rejects unknown ID, wrong secret, scope, purpose and provenance without executing callbacks', async () => {
    const f = await fixture();
    const one = await f.issue();
    const fn = vi.fn(async () => true);
    for (const token of [
      one.token.slice(0, -1) + (one.token.endsWith('a') ? 'b' : 'a'),
      one.token.replace(one.credential.id, 'opc_' + 'f'.repeat(32)),
      one.token.toUpperCase(),
    ])
      await expect(f.service.withCredential(token, {}, fn)).rejects.toMatchObject({
        code: 'unauthenticated',
        message: 'authentication required',
      });
    for (const expected of [
      { orgId: 'org_wrong' },
      { applicationId: 'opa_wrong' },
      { environmentId: 'ope_wrong' },
      { purpose: 'ops:read' },
      { source: 'independent_probe' },
    ])
      await expect(f.service.withCredential(one.token, expected, fn)).rejects.toMatchObject({
        code: 'unauthenticated',
      });
    expect(fn).not.toHaveBeenCalled();
    expect(await f.valid(one.token, f.scope)).toEqual({
      ...f.scope,
      credentialId: one.credential.id,
      purpose: 'events:write',
      source: 'backend_report',
    });
  });
  it('enforces TTL and exact expiry, parent lifecycle and emergency revocation under freeze', async () => {
    const f = await fixture();
    for (const ttlSeconds of [0, 86399, 7776001, 86400.5])
      await expect(
        f.service.issue(principal, f.scope, { ...f.input, ttlSeconds }),
      ).rejects.toMatchObject({ code: 'invalid_request' });
    const one = await f.issue();
    const app = await f.store.find('application', f.scope.orgId, f.scope.applicationId);
    await f.store.transaction(f.scope.orgId, (tx) =>
      tx.update('application', { ...app!, state: 'disabled', version: 2 }, 1),
    );
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    await expect(f.issue()).rejects.toMatchObject({ code: 'conflict' });
    await f.store.transaction(f.scope.orgId, (tx) =>
      tx.update('application', { ...app!, state: 'active', version: 3 }, 2),
    );
    expect(await f.valid(one.token)).toHaveProperty('credentialId', one.credential.id);
    f.advance(DAY);
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    f.deps.assertWritable.mockRejectedValue(new DomainError('frozen', 'test'));
    await expect(f.issue()).rejects.toMatchObject({ code: 'forbidden' });
    await f.service.revoke(principal, f.scope, one.credential.id, f.input);
    await f.service.revoke(principal, f.scope, one.credential.id, f.input);
    expect(
      (await f.audit.list({ orgId: f.scope.orgId })).filter(
        (e) => e.action === 'operations.credential.revoked',
      ),
    ).toHaveLength(1);
  });
  it('rotates with bounded non-extendable overlap, prevents rotation chains during overlap and never resurrects revoked keys', async () => {
    const f = await fixture();
    const one = await f.issue();
    const two = await f.service.rotate(principal, f.scope, one.credential.id, {
      ...f.input,
      overlapSeconds: 3600,
    });
    await f.valid(one.token);
    await f.valid(two.token);
    await expect(
      f.service.rotate(principal, f.scope, two.credential.id, { ...f.input, overlapSeconds: 0 }),
    ).rejects.toMatchObject({ code: 'conflict' });
    await expect(
      f.service.rotate(principal, f.scope, one.credential.id, { ...f.input, overlapSeconds: 0 }),
    ).rejects.toMatchObject({ code: 'conflict' });
    f.advance(3600000);
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    const three = await f.service.rotate(principal, f.scope, two.credential.id, {
      ...f.input,
      overlapSeconds: 0,
    });
    await expect(f.valid(two.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    await f.valid(three.token);
    const nearExpiry = await fixture();
    const short = await nearExpiry.issue();
    nearExpiry.advance(DAY - 600000);
    await nearExpiry.service.rotate(principal, nearExpiry.scope, short.credential.id, {
      ...nearExpiry.input,
      overlapSeconds: 3600,
    });
    expect((await nearExpiry.store.findCredential(short.credential.id))?.expiresAt).toEqual(
      short.credential.expiresAt,
    );
    for (const overlapSeconds of [-1, 3601, 0.1])
      await expect(
        f.service.rotate(principal, f.scope, three.credential.id, { ...f.input, overlapSeconds }),
      ).rejects.toMatchObject({ code: 'invalid_request' });
  });
  it('can atomically replace either of two independent keys with zero overlap without exceeding the cap', async () => {
    const f = await fixture();
    const one = await f.issue(),
      two = await f.issue();
    const replacement = await f.service.rotate(principal, f.scope, one.credential.id, {
      ...f.input,
      overlapSeconds: 0,
    });
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    await f.valid(two.token);
    await f.valid(replacement.token);
    expect(await f.store.listCredentials(f.scope, { limit: 3, activeAt: f.now() })).toHaveLength(2);
    await expect(f.issue()).rejects.toMatchObject({ code: 'conflict' });
  });
  it('atomically rolls back issue, rotation and revoke when audit fails; consumed factors are not replayed', async () => {
    const f = await fixture();
    const spy = vi.spyOn(f.audit, 'appendMany');
    spy.mockRejectedValueOnce(new Error('audit failure'));
    await expect(f.issue()).rejects.toThrow('audit failure');
    expect((await f.service.list(principal, f.scope)).items).toEqual([]);
    expect(f.deps.stepUp).toHaveBeenCalledTimes(1);
    const one = await f.issue();
    spy.mockRejectedValueOnce(new Error('audit failure'));
    await expect(
      f.service.rotate(principal, f.scope, one.credential.id, { ...f.input, overlapSeconds: 0 }),
    ).rejects.toThrow('audit failure');
    await f.valid(one.token);
    expect((await f.service.list(principal, f.scope)).items).toHaveLength(1);
    spy.mockRejectedValueOnce(new Error('audit failure'));
    await expect(f.service.revoke(principal, f.scope, one.credential.id, f.input)).rejects.toThrow(
      'audit failure',
    );
    await f.valid(one.token);
  });
  it('serializes revoke with a callback and refuses expiry before the callback transaction commits', async () => {
    const f = await fixture();
    const one = await f.issue();
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((r) => {
      release = r;
    });
    const ready = new Promise<void>((r) => {
      entered = r;
    });
    const consuming = f.service.withCredential(one.token, {}, async (tx) => {
      entered();
      await held;
      await tx.audit.append({
        actor: { type: 'system' },
        orgId: f.scope.orgId,
        action: 'test.observed',
      });
      return 'committed';
    });
    await ready;
    const revoking = f.service.revoke(principal, f.scope, one.credential.id, f.input);
    release();
    expect(await consuming).toBe('committed');
    await revoking;
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
    const two = await f.issue();
    await expect(
      f.service.withCredential(two.token, {}, async (tx) => {
        await tx.audit.append({
          actor: { type: 'system' },
          orgId: f.scope.orgId,
          action: 'test.must_not_commit',
        });
        f.advance(DAY);
        return true;
      }),
    ).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(
      (await f.audit.list({ orgId: f.scope.orgId })).some(
        (e) => e.action === 'test.must_not_commit',
      ),
    ).toBe(false);
  });
  it('rechecks the live session after step-up and before creating authority', async () => {
    const f = await fixture();
    f.deps.stepUp.mockImplementationOnce(async () => {
      f.deps.sessionActive.mockResolvedValue(false);
    });
    await expect(f.issue()).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(await f.store.listCredentials(f.scope, { limit: 100 })).toEqual([]);
  });
  it('refuses disabled rollout for management and verification', async () => {
    const f = await fixture();
    const one = await f.issue();
    f.deps.enabled = () => false;
    await expect(f.issue()).rejects.toMatchObject({ code: 'not_found' });
    await expect(f.valid(one.token)).rejects.toMatchObject({ code: 'unauthenticated' });
  });
});
