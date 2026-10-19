import { describe, expect, it } from 'vitest';
import { DomainError } from '@trust/shared-types';
import {
  InMemoryPrivilegedStore,
  PrivilegedService,
  type ExternalOperation,
  type PrivilegedRequest,
} from '../src/index.ts';

const T0 = new Date('2026-03-01T00:00:00Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const REQ = { userId: 'usr_req', sessionId: 'ses_req' };
const APP = { userId: 'usr_app', sessionId: 'ses_app' };
const GOOD = '123456';

function setup(over?: { witness?: boolean; failWith?: Error }) {
  let now = T0;
  const store = new InMemoryPrivilegedStore();
  const stepUps: string[] = [];
  const ran: Array<{ op: string; id: string }> = [];
  const runner = (op: ExternalOperation) => async (r: PrivilegedRequest) => {
    ran.push({ op, id: r.id });
    if (over?.failWith) throw over.failWith;
  };
  const svc = new PrivilegedService({
    store,
    clock: { now: () => now },
    config: { dualControlLicenseRevoke: true, witnessConfigured: over?.witness ?? true },
    stepUp: async (p, code) => {
      stepUps.push(p.userId);
      if (code !== GOOD) throw new DomainError('unauthenticated', 'invalid credentials or code');
    },
    validateTarget: async (_op, orgId, targetId) => {
      if (orgId === 'org_missing' || targetId === 'missing')
        throw new DomainError('not_found', 'not found');
    },
    orgExists: async (orgId) => orgId !== 'org_missing',
    run: {
      'license.revoke': runner('license.revoke'),
      'operator.grant': runner('operator.grant'),
      'operator.revoke': runner('operator.revoke'),
    },
  });
  const audited = () => store.committedAudit.map((e) => e.action);
  const advance = (ms: number) => void (now = new Date(now.getTime() + ms));
  const revoke = () =>
    svc.create(REQ.userId, {
      operation: 'license.revoke',
      orgId: 'org_a',
      targetId: 'lic_1',
      reason: 'fraudulent purchase',
    });
  return { svc, store, stepUps, ran, audited, advance, revoke };
}

const code = (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) => (e instanceof DomainError ? e.code : `unexpected: ${String(e)}`),
  );

describe('privileged requests', () => {
  it('validates the operation’s exact target and a reason, and audits the request', async () => {
    const { svc, revoke, audited } = setup();
    const ops = (input: Parameters<typeof svc.create>[1]) => code(svc.create(REQ.userId, input));
    expect(await ops({ operation: 'license.revoke', targetId: 'lic_1', reason: 'reason' })).toBe(
      'invalid_request',
    );
    expect(
      await ops({ operation: 'platform.unfreeze', targetId: 'x', reason: 'reason here' }),
    ).toBe('invalid_request');
    expect(await ops({ operation: 'operator.grant', targetId: 'usr_x', reason: ' ' })).toBe(
      'invalid_request',
    );
    expect(
      await ops({ operation: 'operator.grant', targetId: 'missing', reason: 'new hire' }),
    ).toBe('not_found');
    expect(await ops({ operation: 'org.unfreeze', orgId: 'org_a', reason: 'all clear' })).toBe(
      'conflict',
    );
    expect(await ops({ operation: 'nonsense' as never, reason: 'reason' })).toBe('invalid_request');
    const r = await revoke();
    expect(r).toMatchObject({ status: 'pending', requestedBy: REQ.userId, targetId: 'lic_1' });
    expect(r.expiresAt.getTime() - T0.getTime()).toBe(24 * HOUR);
    expect(audited()).toEqual(['privileged.requested']);
  });

  it('needs a distinct operator with a fresh code to approve; the requester never decides', async () => {
    const { svc, revoke, stepUps, audited } = setup();
    const r = await revoke();
    expect(await code(svc.approve(REQ, r.id, 'looks right', GOOD))).toBe('forbidden');
    expect(await code(svc.reject(REQ.userId, r.id, 'changed my mind'))).toBe('forbidden');
    expect(stepUps).toEqual([]); // refused before any factor was consumed
    expect(await code(svc.approve(APP, r.id, 'looks right', '000000'))).toBe('unauthenticated');
    expect((await svc.get(r.id)).status).toBe('pending');
    const ok = await svc.approve(APP, r.id, 'verified with finance', GOOD);
    expect(ok).toMatchObject({ status: 'approved', decidedBy: APP.userId });
    expect(ok.executeBefore!.getTime() - T0.getTime()).toBe(HOUR);
    // replay and late decisions fail
    expect(await code(svc.approve(APP, r.id, 'again', GOOD))).toBe('conflict');
    expect(await code(svc.reject('usr_other', r.id, 'too late'))).toBe('conflict');
    expect(audited()).toEqual(['privileged.requested', 'privileged.approved']);
  });

  it('expires pending requests after 24 hours and grants after one hour', async () => {
    const { svc, revoke, advance, ran } = setup();
    const stale = await revoke();
    advance(24 * HOUR);
    expect((await svc.get(stale.id)).status).toBe('expired');
    expect(await code(svc.approve(APP, stale.id, 'late approval', GOOD))).toBe('conflict');
    const r = await revoke();
    await svc.approve(APP, r.id, 'approved', GOOD);
    advance(HOUR);
    expect((await svc.get(r.id)).status).toBe('expired');
    expect(await code(svc.execute(REQ.userId, r.id, 'run it'))).toBe('conflict');
    expect(ran).toEqual([]);
    expect((await svc.list('expired')).map((x) => x.id).sort()).toEqual([stale.id, r.id].sort());
  });

  it('lets only the requester execute, exactly once, with the stored target', async () => {
    const { svc, revoke, ran, audited } = setup();
    const r = await revoke();
    expect(await code(svc.execute(REQ.userId, r.id, 'run it'))).toBe('conflict'); // not approved yet
    await svc.approve(APP, r.id, 'approved', GOOD);
    expect(await code(svc.execute(APP.userId, r.id, 'run it'))).toBe('forbidden');
    const done = await svc.execute(REQ.userId, r.id, 'run it');
    expect(done.status).toBe('executed');
    expect(ran).toEqual([{ op: 'license.revoke', id: r.id }]);
    expect(await code(svc.execute(REQ.userId, r.id, 'run it again'))).toBe('conflict');
    expect(ran).toHaveLength(1);
    expect(audited()).toEqual([
      'privileged.requested',
      'privileged.approved',
      'privileged.execution_started',
      'privileged.executed',
    ]);
  });

  it('records a failed operation, surfaces its error and never re-runs it', async () => {
    const { svc, revoke, ran, audited } = setup({
      failWith: new DomainError('conflict', 'cannot revoke a license in state revoked'),
    });
    const r = await revoke();
    await svc.approve(APP, r.id, 'approved', GOOD);
    expect(await code(svc.execute(REQ.userId, r.id, 'run it'))).toBe('conflict');
    expect(await svc.get(r.id)).toMatchObject({ status: 'failed', failure: 'conflict' });
    expect(await code(svc.execute(REQ.userId, r.id, 'retry'))).toBe('conflict');
    expect(ran).toHaveLength(1);
    expect(audited().at(-1)).toBe('privileged.execution_failed');
  });

  it('lets one of two concurrent approvers win', async () => {
    const { svc, revoke } = setup();
    const r = await revoke();
    const out = await Promise.all([
      code(svc.approve(APP, r.id, 'first', GOOD)),
      code(svc.approve({ userId: 'usr_app2', sessionId: 's2' }, r.id, 'second', GOOD)),
    ]);
    expect(out.sort()).toEqual(['conflict', 'ok']);
  });

  it('cancels only by the requester and only before execution', async () => {
    const { svc, revoke, ran } = setup();
    const r = await revoke();
    expect(await code(svc.cancel(APP.userId, r.id, 'not mine'))).toBe('forbidden');
    await svc.approve(APP, r.id, 'approved', GOOD);
    expect((await svc.cancel(REQ.userId, r.id, 'no longer needed')).status).toBe('cancelled');
    expect(await code(svc.execute(REQ.userId, r.id, 'run it'))).toBe('conflict');
    expect(ran).toEqual([]);
  });
});

describe('freeze', () => {
  it('stops grant-extending writes for the scope only; lifting needs dual control', async () => {
    const { svc, audited } = setup();
    expect(await code(svc.freeze(REQ.userId, 'org_missing', 'incident'))).toBe('not_found');
    await svc.freeze(REQ.userId, 'org_a', 'suspected account takeover');
    expect(await code(svc.freeze(APP.userId, 'org_a', 'again'))).toBe('conflict');
    expect(await code(svc.assertWritable('org_a'))).toBe('frozen');
    expect(await code(svc.assertWritable('org_b'))).toBe('ok');
    expect(await code(svc.assertWritable(null))).toBe('ok');
    const lift = await svc.create(REQ.userId, {
      operation: 'org.unfreeze',
      orgId: 'org_a',
      reason: 'investigation closed',
    });
    expect(await code(svc.execute(REQ.userId, lift.id, 'lift'))).toBe('conflict');
    await svc.approve(APP, lift.id, 'confirmed closed', GOOD);
    expect((await svc.execute(REQ.userId, lift.id, 'lift')).status).toBe('executed');
    expect(await code(svc.assertWritable('org_a'))).toBe('ok');
    expect(audited()).toContain('privileged.unfrozen');
  });

  it('a platform freeze blocks every organization and operator grants', async () => {
    const { svc, ran } = setup();
    const grant = await svc.create(REQ.userId, {
      operation: 'operator.grant',
      targetId: 'usr_new',
      reason: 'new on-call engineer',
    });
    await svc.approve(APP, grant.id, 'approved', GOOD);
    await svc.freeze(APP.userId, null, 'platform incident');
    expect(await code(svc.assertWritable('org_b'))).toBe('frozen');
    expect(await code(svc.assertWritable(null))).toBe('frozen');
    expect(await code(svc.execute(REQ.userId, grant.id, 'grant'))).toBe('frozen');
    expect(ran).toEqual([]);
    expect((await svc.get(grant.id)).status).toBe('approved'); // still usable once unfrozen
  });
});

describe('break-glass', () => {
  it('is refused without an external witness', async () => {
    const { svc, revoke, stepUps } = setup({ witness: false });
    const r = await revoke();
    expect(await code(svc.breakGlass(REQ, r.id, 'nobody else on call', GOOD))).toBe('conflict');
    expect(stepUps).toEqual([]);
  });

  it('self-approves with a fresh code, is usable only once witnessed, for 15 minutes, once per day', async () => {
    const { svc, revoke, ran, advance, audited } = setup();
    const r = await revoke();
    expect(await code(svc.breakGlass(APP, r.id, 'not my request', GOOD))).toBe('forbidden');
    expect(await code(svc.breakGlass(REQ, r.id, 'nobody else on call', '999999'))).toBe(
      'unauthenticated',
    );
    const bg = await svc.breakGlass(REQ, r.id, 'nobody else on call', GOOD);
    expect(bg).toMatchObject({ status: 'approved', breakGlass: true, decidedBy: REQ.userId });
    expect(bg.executeBefore!.getTime() - T0.getTime()).toBe(15 * MIN);
    expect(await code(svc.execute(REQ.userId, r.id, 'run'))).toBe('conflict'); // not witnessed
    await svc.markWitnessed(r.id, 'anc_1');
    expect(await code(svc.markWitnessed(r.id, 'anc_2'))).toBe('conflict');
    expect((await svc.execute(REQ.userId, r.id, 'run')).status).toBe('executed');
    expect(ran).toHaveLength(1);
    expect(audited()).toContain('privileged.break_glass_witnessed');

    const second = await revoke();
    expect(await code(svc.breakGlass(REQ, second.id, 'again', GOOD))).toBe('conflict');
    advance(24 * HOUR + MIN);
    const third = await revoke();
    expect((await svc.breakGlass(REQ, third.id, 'next day', GOOD)).status).toBe('approved');
    advance(15 * MIN);
    await svc.markWitnessed(third.id, 'anc_3');
    expect(await code(svc.execute(REQ.userId, third.id, 'run'))).toBe('conflict'); // grant expired
  });
});
