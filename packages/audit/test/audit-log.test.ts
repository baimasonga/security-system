import { describe, expect, it } from 'vitest';
import {
  InMemoryAuditLog,
  GENESIS_HASH,
  chainFor,
  computeAnchor,
  computeEventHash,
  isOrgChain,
  verifyEvents,
} from '../src/index.ts';

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
        nested: { access_token: 'zz-needle-token-zz' },
        licenseKey: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
        innocuous: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE',
      },
    });
    expect(JSON.stringify(e)).not.toMatch(/hunter2|zz-needle-token-zz|LK-AAAAA/);
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
    expect(verifyEvents([], new Map())).toMatchObject({ ok: true, count: 0, chains: 0 });
  });
});

describe('partitioned chains (ADR-008): tamper evidence per chain', () => {
  const ev = (orgId: string | undefined, n: number) => ({
    actor: { type: 'system' as const },
    action: `a${n}`,
    ...(orgId ? { orgId } : {}),
    target: { type: 'activation', id: `act_${n}` },
  });

  async function twoOrgs() {
    const log = new InMemoryAuditLog(clock);
    for (let i = 0; i < 4; i++) {
      await log.append(ev('org_a', i));
      await log.append(ev('org_b', i));
    }
    await log.append(ev(undefined, 9));
    return log;
  }

  it('an event cannot be moved into another chain (the chain id is part of the hash)', async () => {
    const log = await twoOrgs();
    const all = await log.list();
    const a1 = all.find((e) => e.chain === 'org:org_a' && e.seq === 1)!;
    const idx = all.indexOf(a1);
    log.unsafeReplaceForTest(idx, { ...a1, chain: 'org:org_b' });
    expect(await log.verifyChain()).toMatchObject({ ok: false });
    // even a forger who recomputes the hash cannot make it fit: seq/prev_hash belong to the other chain
    const { hash: _h, ...rest } = { ...a1, chain: 'org:org_b' };
    void _h;
    log.unsafeReplaceForTest(idx, { ...a1, chain: 'org:org_b', hash: computeEventHash(rest) });
    expect(await log.verifyChain()).toMatchObject({ ok: false });
  });

  it('truncating the tail of one chain is caught by the stored head', async () => {
    const log = await twoOrgs();
    const all = await log.list();
    const lastA = all.filter((e) => e.chain === 'org:org_a').at(-1)!;
    log.unsafeDeleteForTest(all.indexOf(lastA));
    expect(await log.verifyChain()).toMatchObject({
      ok: false,
      chain: 'org:org_a',
      reason: expect.stringContaining('head'),
    });
    // other tenants' verification is unaffected and independent
    expect(await log.verifyChain({ orgId: 'org_b' })).toMatchObject({
      ok: true,
      count: 4,
      chains: 1,
    });
  });

  it('a rolled-back or missing head record is detected', async () => {
    const log = await twoOrgs();
    log.unsafeSetHeadForTest('org:org_b', { seq: 2, hash: GENESIS_HASH });
    expect(await log.verifyChain()).toMatchObject({ ok: false, chain: 'org:org_b' });
    const log2 = await twoOrgs();
    log2.unsafeSetHeadForTest('org:org_a', undefined);
    expect(await log2.verifyChain()).toMatchObject({
      ok: false,
      chain: 'org:org_a',
      reason: expect.stringContaining('no head'),
    });
  });

  it('a head with no events (whole chain deleted) is detected', async () => {
    const log = await twoOrgs();
    for (;;) {
      const i = (await log.list()).findIndex((x) => x.chain === 'org:org_a');
      if (i < 0) break;
      log.unsafeDeleteForTest(i);
    }
    expect(await log.verifyChain()).toMatchObject({ ok: false, chain: 'org:org_a' });
  });

  it('org-scoped verification checks only that organization (and not look-alike ids)', async () => {
    const log = new InMemoryAuditLog(clock);
    await log.append(ev('org_1', 1));
    await log.append(ev('org_10', 1));
    await log.append(ev('org_10', 2));
    expect(await log.verifyChain({ orgId: 'org_1' })).toMatchObject({
      ok: true,
      count: 1,
      chains: 1,
    });
    expect(await log.verifyChain({ orgId: 'org_10' })).toMatchObject({
      ok: true,
      count: 2,
      chains: 1,
    });
    expect(await log.verifyChain({ orgId: 'org_nope' })).toMatchObject({
      ok: true,
      count: 0,
      chains: 0,
    });
  });
});

describe('chain assignment and anchor', () => {
  it('maps events to chains deterministically and escapes ids so chains cannot collide', () => {
    expect(chainFor({ actor: { type: 'user' }, action: 'x' })).toBe('system');
    expect(chainFor({ actor: { type: 'user' }, action: 'x', orgId: 'org_1' })).toBe('org:org_1');
    // a hostile org id cannot impersonate a shard of another org
    expect(chainFor({ actor: { type: 'user' }, action: 'x', orgId: 'org_1#3' }, 1)).toBe(
      'org:org_1%233',
    );
    expect(isOrgChain('org:org_1#3', 'org_1')).toBe(true);
    expect(isOrgChain('org:org_1%233', 'org_1')).toBe(false);
    expect(isOrgChain('org:org_10', 'org_1')).toBe(false);
  });

  it('shards are stable per target, spread across targets, and bounded', () => {
    const at = (id: string) =>
      chainFor(
        {
          actor: { type: 'device' },
          action: 'x',
          orgId: 'org_1',
          target: { type: 'activation', id },
        },
        8,
      );
    expect(at('act_same')).toBe(at('act_same'));
    const seen = new Set(Array.from({ length: 200 }, (_, i) => at(`act_${i}`)));
    expect(seen.size).toBe(8);
    for (const c of seen) expect(c).toMatch(/^org:org_1#[0-7]$/);
    expect(() => chainFor({ actor: { type: 'user' }, action: 'x', orgId: 'o' }, 1000)).toThrow(
      /shard/,
    );
  });

  it('the anchor is order-independent and changes with any head', () => {
    const heads = [
      { chain: 'org:a', seq: 3, hash: 'h3' },
      { chain: 'system', seq: 1, hash: 'h1' },
    ];
    const a = computeAnchor(heads);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(computeAnchor([...heads].reverse())).toBe(a);
    expect(computeAnchor([{ ...heads[0]!, seq: 4 }, heads[1]!])).not.toBe(a);
    expect(computeAnchor([{ ...heads[0]!, hash: 'hx' }, heads[1]!])).not.toBe(a);
    expect(computeAnchor([...heads, { chain: 'org:b', seq: 1, hash: 'x' }])).not.toBe(a);
  });
});
