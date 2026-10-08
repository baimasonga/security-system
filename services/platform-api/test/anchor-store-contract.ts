import { describe, expect, it } from 'vitest';
import type { AnchorRecord, AnchorStore } from '../src/anchors.ts';

const rec = (n: number, over: Partial<AnchorRecord> = {}): AnchorRecord => ({
  id: `anc_${n.toString().padStart(4, '0')}`,
  createdAt: new Date(Date.UTC(2026, 0, 1, 0, n)),
  anchor: n.toString(16).padStart(64, '0'),
  chains: n,
  events: n * 10,
  destination: 'https://witness.example/anchors',
  status: 'published',
  receipt: `r${n}`,
  error: null,
  ...over,
});

/** One definition of correct AnchorStore behaviour, run against every adapter. */
export function anchorStoreContract(name: string, make: () => AnchorStore | Promise<AnchorStore>) {
  describe(`AnchorStore contract: ${name}`, () => {
    it('is empty at first', async () => {
      const s = await make();
      expect(await s.latest()).toBeUndefined();
      expect(await s.latest('published')).toBeUndefined();
      expect(await s.list(10)).toEqual([]);
    });

    it('round-trips records; latest/list are newest first; latest can filter by status', async () => {
      const s = await make();
      await s.record(rec(1));
      await s.record(rec(2, { status: 'failed', receipt: null, error: 'witness unreachable' }));
      await s.record(rec(3));
      await s.record(rec(4, { status: 'failed', receipt: null, error: 'witness responded 500' }));
      expect(await s.latest()).toEqual(
        rec(4, { status: 'failed', receipt: null, error: 'witness responded 500' }),
      );
      expect(await s.latest('published')).toEqual(rec(3));
      expect((await s.list(10)).map((r) => r.id)).toEqual([
        'anc_0004',
        'anc_0003',
        'anc_0002',
        'anc_0001',
      ]);
      expect((await s.list(2)).map((r) => r.id)).toEqual(['anc_0004', 'anc_0003']);
      expect((await s.list(10)).at(-1)).toEqual(rec(1));
    });

    it('returns copies, not live references', async () => {
      const s = await make();
      await s.record(rec(1));
      const a = (await s.latest())!;
      a.receipt = 'tampered';
      expect((await s.latest())!.receipt).toBe('r1');
    });
  });
}
