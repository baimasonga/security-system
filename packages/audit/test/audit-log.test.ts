import { describe, expect, it } from 'vitest';
import { InMemoryAuditLog, verifyEvents, GENESIS_HASH } from '../src/index.ts';

const clock = { now: () => new Date('2026-01-01T00:00:00Z') };

async function filled(n = 5) {
  const log = new InMemoryAuditLog(clock);
  for (let i = 0; i < n; i++) {
    await log.append({
      actor: { type: 'operator', id: 'usr_1' },
      action: 'license.revoked',
      target: { type: 'license', id: `lic_${i}` },
      orgId: 'org_1',
      reason: 'chargeback',
      metadata: { i },
    });
  }
  return log;
}

describe('audit log', () => {
  it('builds a verifiable hash chain starting at genesis', async () => {
    const log = await filled();
    const all = await log.list();
    expect(all[0]!.prevHash).toBe(GENESIS_HASH);
    expect(all.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5]);
    const v = await log.verifyChain();
    expect(v).toMatchObject({ ok: true, count: 5 });
  });

  it('detects modified content', async () => {
    const log = await filled();
    const e = (await log.list())[2]!;
    log.unsafeReplaceForTest(2, { ...e, reason: 'nothing to see' });
    expect(await log.verifyChain()).toMatchObject({ ok: false, brokenAtSeq: 3 });
  });

  it('detects deleted entries (gap) and truncated-middle edits', async () => {
    const log = await filled();
    log.unsafeDeleteForTest(1);
    expect(await log.verifyChain()).toMatchObject({ ok: false });
  });

  it('detects a recomputed-hash forgery because the next link breaks', async () => {
    const log = await filled();
    const evs = await log.list();
    const forged = { ...evs[1]!, reason: 'forged' };
    // attacker recomputes this entry's own hash but cannot fix every later link
    const { hash: _h, ...rest } = forged;
    void _h;
    const { computeEventHash } = await import('../src/index.ts');
    forged.hash = computeEventHash(rest);
    log.unsafeReplaceForTest(1, forged);
    expect(await log.verifyChain()).toMatchObject({ ok: false, brokenAtSeq: 3 });
  });

  it('redacts secrets from metadata instead of persisting them', async () => {
    const log = new InMemoryAuditLog(clock);
    const e = await log.append({
      actor: { type: 'user', id: 'usr_1' },
      action: 'x',
      metadata: {
        password: 'hunter2',
        note: 'ok',
        nested: { access_token: 'abc' },
        licenseKey: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
        innocuous: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
      },
    });
    expect(JSON.stringify(e)).not.toMatch(/hunter2|abc|LK-AAAAA/);
    expect(e.metadata['note']).toBe('ok');
  });

  it('keeps the chain intact under concurrent appends', async () => {
    const log = new InMemoryAuditLog(clock);
    await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        log.append({ actor: { type: 'system' }, action: `a${i}` }),
      ),
    );
    expect(await log.verifyChain()).toMatchObject({ ok: true, count: 50 });
  });

  it('filters by org without leaking other orgs', async () => {
    const log = new InMemoryAuditLog(clock);
    await log.append({ actor: { type: 'system' }, action: 'a', orgId: 'org_1' });
    await log.append({ actor: { type: 'system' }, action: 'b', orgId: 'org_2' });
    expect((await log.list({ orgId: 'org_1' })).map((e) => e.action)).toEqual(['a']);
    expect(verifyEvents([])).toMatchObject({ ok: true, count: 0 });
  });
});
