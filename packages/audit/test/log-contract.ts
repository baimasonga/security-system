import { describe, expect, it } from 'vitest';
import { GENESIS_HASH, type AuditLog } from '../src/index.ts';

const clock = { now: () => new Date('2026-01-01T00:00:00.123Z') };

/** One definition of correct AuditLog behaviour, run against every adapter. */
export function auditLogContract(
  name: string,
  make: (clock: { now(): Date }) => AuditLog | Promise<AuditLog>,
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
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 1, headHash: e.hash });
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
        });
      expect((await log.list({ orgId: 'org_1' })).map((e) => e.seq)).toEqual([1, 2, 3]);
      expect((await log.list({ action: 'even' })).map((e) => e.seq)).toEqual([2, 4]);
      expect((await log.list({ limit: 2 })).map((e) => e.seq)).toEqual([4, 5]);
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
  });
}
