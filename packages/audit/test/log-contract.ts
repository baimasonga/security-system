import { describe, expect, it } from 'vitest';
import { GENESIS_HASH, type AuditLog } from '../src/index.ts';

const clock = { now: () => new Date('2026-01-01T00:00:00.123Z') };

/** One definition of correct AuditLog behaviour, run against every adapter. */
export function auditLogContract(
  name: string,
  make: (clock: { now(): Date }, opts?: { shards?: number }) => AuditLog | Promise<AuditLog>,
) {
  describe(`AuditLog contract: ${name}`, () => {
    it('starts at genesis, numbers events from 1, and verifies', async () => {
      const log = await make(clock);
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 0 });
      const e = await log.append({
        actor: { type: 'operator', id: 'usr_1' },
        action: 'license.revoked',
        target: { type: 'license', id: 'lic_1' },
        orgId: 'org_1',
        reason: 'chargeback',
        metadata: { n: 1, nested: { a: [1, 2] } },
      });
      expect(e).toMatchObject({
        seq: 1,
        prevHash: GENESIS_HASH,
        occurredAt: '2026-01-01T00:00:00.123Z',
      });
      expect(e.chain).toBe('org:org_1');
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 1, chains: 1 });
    });

    it('stores what it returns: listed events equal appended events (hash survives storage round-trip)', async () => {
      const log = await make(clock);
      const a = await log.append({
        actor: { type: 'user', id: 'usr_1' },
        action: 'x',
        target: { type: 'org', id: 'org_1' },
        orgId: 'org_1',
        metadata: { z: 1, a: 'é✓', nested: { b: null, c: true } },
      });
      const b = await log.append({ actor: { type: 'anonymous' }, action: 'y' });
      expect(await log.list()).toEqual([a, b]);
      expect(b.actor).toEqual({ type: 'anonymous', id: null });
      expect(b.target).toBeNull();
    });

    it('keeps one linear chain under heavy concurrent appends', async () => {
      const log = await make(clock);
      const evs = await Promise.all(
        Array.from({ length: 40 }, (_, i) =>
          log.append({ actor: { type: 'system' }, action: `a${i}` }),
        ),
      );
      expect(new Set(evs.map((e) => e.seq)).size).toBe(40);
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 40 });
    });

    it('filters by org and action; limit returns the newest events oldest-first', async () => {
      const log = await make(clock);
      for (let i = 1; i <= 5; i++)
        await log.append({
          actor: { type: 'system' },
          action: i % 2 ? 'odd' : 'even',
          orgId: i <= 3 ? 'org_1' : 'org_2',
          metadata: { i },
        });
      const ids = (evs: Array<{ metadata: Record<string, unknown> }>) =>
        evs.map((e) => e.metadata['i']);
      expect(ids(await log.list({ orgId: 'org_1' }))).toEqual([1, 2, 3]);
      expect(ids(await log.list({ action: 'even' }))).toEqual([2, 4]);
      expect(ids(await log.list({ limit: 2 }))).toEqual([4, 5]);
      expect(await log.list({ orgId: 'org_none' })).toEqual([]);
    });

    it('redacts secrets and survives NUL characters instead of failing the write', async () => {
      const log = await make(clock);
      const e = await log.append({
        actor: { type: 'user', id: 'usr_1' },
        action: 'x',
        metadata: { password: 'hunter2', note: 'a\u0000b' },
      });
      expect(JSON.stringify(e)).not.toContain('hunter2');
      expect(e.metadata['note']).toBe('ab');
      expect(await log.verifyChain()).toMatchObject({ ok: true });
    });

    it('appendMany writes a contiguous run, in order, even while other appends race', async () => {
      const log = await make(clock);
      const batch = (tag: string) =>
        Array.from({ length: 5 }, (_, i) => ({
          actor: { type: 'system' as const },
          action: `${tag}${i}`,
        }));
      const all = await Promise.all([
        log.appendMany(batch('a')),
        log.appendMany(batch('b')),
        log.append({ actor: { type: 'system' }, action: 'single' }),
        log.appendMany(batch('c')),
      ]);
      for (const run of [all[0], all[1], all[3]]) {
        const seqs = run.map((e) => e.seq);
        expect(seqs).toEqual(Array.from({ length: 5 }, (_, i) => seqs[0]! + i)); // contiguous
        expect(run.map((e) => e.action).map((a) => a.slice(1))).toEqual(['0', '1', '2', '3', '4']);
      }
      expect(await log.appendMany([])).toEqual([]);
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 16 });
    });

    it('rejects a malformed event without writing anything, including the rest of its batch', async () => {
      const log = await make(clock);
      await log.append({ actor: { type: 'system' }, action: 'ok' });
      await expect(
        log.appendMany([
          { actor: { type: 'system' }, action: 'first' },
          { actor: { type: 'bogus' as never }, action: 'bad' },
        ]),
      ).rejects.toThrow();
      expect((await log.list()).map((e) => e.action)).toEqual(['ok']);
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 1 });
    });

    describe('partitioned chains (ADR-008)', () => {
      const ev = (orgId: string | undefined, n: number) => ({
        actor: { type: 'system' as const },
        action: `e${n}`,
        ...(orgId ? { orgId } : {}),
        target: { type: 'activation', id: `act_${n}` },
      });

      it('organizations and the system get independent chains, each starting at genesis', async () => {
        const log = await make(clock);
        const [a1, b1, s1, a2] = await Promise.all([
          log.append(ev('org_a', 1)),
          log.append(ev('org_b', 1)),
          log.append(ev(undefined, 1)),
          log.append(ev('org_a', 2)),
        ]);
        expect(new Set([a1.chain, b1.chain, s1.chain])).toEqual(
          new Set(['org:org_a', 'org:org_b', 'system']),
        );
        expect([b1.seq, s1.seq]).toEqual([1, 1]);
        expect([b1.prevHash, s1.prevHash]).toEqual([GENESIS_HASH, GENESIS_HASH]);
        expect([a1.seq, a2.seq].sort()).toEqual([1, 2]);
        const v = await log.verifyChain();
        expect(v).toMatchObject({ ok: true, count: 4, chains: 3 });
        expect((v as { anchor: string }).anchor).toMatch(/^[0-9a-f]{64}$/);
      });

      it('the anchor is stable when nothing changes and moves when anything is appended', async () => {
        const log = await make(clock);
        await log.append(ev('org_a', 1));
        const first = (await log.verifyChain()) as { anchor: string };
        expect(((await log.verifyChain()) as { anchor: string }).anchor).toBe(first.anchor);
        await log.append(ev('org_b', 1));
        expect(((await log.verifyChain()) as { anchor: string }).anchor).not.toBe(first.anchor);
      });

      it('verifies a single organization without touching others, and does not confuse look-alike ids', async () => {
        const log = await make(clock);
        await log.appendMany([ev('org_1', 1), ev('org_1', 2), ev('org_10', 1), ev(undefined, 1)]);
        expect(await log.verifyChain({ orgId: 'org_1' })).toMatchObject({
          ok: true,
          count: 2,
          chains: 1,
        });
        expect(await log.verifyChain({ orgId: 'org_10' })).toMatchObject({
          ok: true,
          count: 1,
          chains: 1,
        });
        expect(await log.verifyChain({ orgId: 'org_zzz' })).toMatchObject({
          ok: true,
          count: 0,
          chains: 0,
        });
      });

      it('a batch spanning chains is all-or-nothing', async () => {
        const log = await make(clock);
        await log.append(ev('org_a', 0));
        await expect(
          log.appendMany([
            ev('org_a', 1),
            ev('org_b', 1),
            { actor: { type: 'bogus' as never }, action: 'bad', orgId: 'org_c' },
          ]),
        ).rejects.toThrow();
        expect((await log.list()).map((e) => e.action)).toEqual(['e0']);
        expect(await log.verifyChain()).toMatchObject({ ok: true, count: 1, chains: 1 });
        // and the chains it would have created do not exist afterwards
        await log.append(ev('org_b', 7));
        expect((await log.list({ orgId: 'org_b' }))[0]).toMatchObject({
          chain: 'org:org_b',
          seq: 1,
        });
      });

      it('concurrent appends to different organizations all succeed with gap-free per-chain sequences', async () => {
        const log = await make(clock);
        const orgs = ['org_a', 'org_b', 'org_c', 'org_d'];
        await Promise.all(Array.from({ length: 80 }, (_, i) => log.append(ev(orgs[i % 4], i))));
        expect(await log.verifyChain()).toMatchObject({ ok: true, count: 80, chains: 4 });
        for (const o of orgs) {
          const seqs = (await log.list({ orgId: o })).map((e) => e.seq).sort((x, y) => x - y);
          expect(seqs).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
        }
      });

      it('with sharding a hot organization spreads over several chains, a target stays on one, and everything verifies', async () => {
        const log = await make(clock, { shards: 4 });
        await Promise.all(Array.from({ length: 60 }, (_, i) => log.append(ev('org_hot', i % 30))));
        const evs = await log.list({ orgId: 'org_hot' });
        const chains = new Set(evs.map((e) => e.chain));
        expect(chains.size).toBeGreaterThan(1);
        for (const c of chains) expect(c).toMatch(/^org:org_hot#[0-3]$/);
        const byTarget = new Map<string, Set<string>>();
        for (const e of evs)
          (
            byTarget.get(e.target!.id) ?? byTarget.set(e.target!.id, new Set()).get(e.target!.id)!
          ).add(e.chain!);
        for (const set of byTarget.values()) expect(set.size).toBe(1);
        expect(await log.verifyChain()).toMatchObject({ ok: true, count: 60 });
        expect(await log.verifyChain({ orgId: 'org_hot' })).toMatchObject({
          ok: true,
          count: 60,
          chains: chains.size,
        });
      });
    });
  });
}
