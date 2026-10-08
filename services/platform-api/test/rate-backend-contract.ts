import { describe, expect, it } from 'vitest';
import type { RateBackend } from '../src/rate-limit.ts';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One definition of correct fixed-window counting, run against every backend. */
export function rateBackendContract(name: string, make: () => RateBackend | Promise<RateBackend>) {
  describe(`RateBackend contract: ${name}`, () => {
    it('counts within a window, reports the time left, and keeps buckets independent', async () => {
      const b = await make();
      const first = await b.incr('login|1.2.3.4', 60_000);
      expect(first.current).toBe(1);
      expect(first.ttl).toBeGreaterThan(55_000);
      expect(first.ttl).toBeLessThanOrEqual(60_000);
      expect((await b.incr('login|1.2.3.4', 60_000)).current).toBe(2);
      expect((await b.incr('login|1.2.3.4', 60_000)).current).toBe(3);
      expect((await b.incr('login|5.6.7.8', 60_000)).current).toBe(1); // another client
      expect((await b.incr('register|1.2.3.4', 60_000)).current).toBe(1); // another route
      const again = await b.incr('login|1.2.3.4', 60_000);
      expect(again.current).toBe(4);
      expect(again.ttl).toBeLessThanOrEqual(first.ttl);
    });

    it('starts a new window once the old one has ended', async () => {
      const b = await make();
      expect((await b.incr('k', 150)).current).toBe(1);
      expect((await b.incr('k', 150)).current).toBe(2);
      await sleep(260);
      const fresh = await b.incr('k', 150);
      expect(fresh.current).toBe(1);
      expect(fresh.ttl).toBeGreaterThan(0);
    });

    it('does not lose counts under concurrency: 60 parallel requests are counted 1..60 exactly once', async () => {
      const b = await make();
      const rs = await Promise.all(Array.from({ length: 60 }, () => b.incr('hot', 60_000)));
      expect(rs.map((r) => r.current).sort((x, y) => x - y)).toEqual(
        Array.from({ length: 60 }, (_, i) => i + 1),
      );
    });

    it('purges only windows that have ended', async () => {
      const b = await make();
      await b.incr('short-a', 100);
      await b.incr('short-b', 100);
      await b.incr('long', 60_000);
      await sleep(220);
      expect(await b.purgeExpired()).toBe(2);
      expect((await b.incr('long', 60_000)).current).toBe(2); // the live window survived
      expect(await b.purgeExpired()).toBe(0);
    });
  });
}
