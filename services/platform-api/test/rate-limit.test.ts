import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';
import {
  MemoryRateBackend,
  ResilientRateBackend,
  fastifyRateStore,
  type RateBackend,
} from '../src/rate-limit.ts';
import { rateBackendContract } from './rate-backend-contract.ts';

rateBackendContract('memory', () => new MemoryRateBackend());

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;

describe('MemoryRateBackend bounds', () => {
  it('never holds more than maxBuckets windows, even under a flood of distinct keys', async () => {
    const b = new MemoryRateBackend({ maxBuckets: 100 });
    for (let i = 0; i < 1000; i++) await b.incr(`ip-${i}`, 60_000);
    expect(b.size).toBeLessThanOrEqual(100);
  });

  it('truncates absurdly long buckets instead of storing them', async () => {
    const b = new MemoryRateBackend();
    expect((await b.incr('x'.repeat(5000), 1000)).current).toBe(1);
    expect((await b.incr('x'.repeat(5000), 1000)).current).toBe(2);
  });
});

describe('ResilientRateBackend', () => {
  const failing = (): RateBackend & { calls: number } => ({
    calls: 0,
    async incr() {
      this.calls++;
      throw new Error('connection refused to postgres://user:secret@db');
    },
    async purgeExpired() {
      return 0;
    },
  });

  it('uses the primary while it works', async () => {
    const reasons: string[] = [];
    const primary = new MemoryRateBackend();
    const r = new ResilientRateBackend(primary, new MemoryRateBackend(), {
      onFallback: (x) => reasons.push(x),
    });
    expect((await r.incr('k', 1000)).current).toBe(1);
    expect((await r.incr('k', 1000)).current).toBe(2);
    expect(reasons).toEqual([]);
  });

  it('falls back to local counting on error (never weaker than per-process), then stays off the primary for the breaker period', async () => {
    const reasons: string[] = [];
    const primary = failing();
    const r = new ResilientRateBackend(primary, new MemoryRateBackend(), {
      breakerMs: 120,
      onFallback: (x) => reasons.push(x),
    });
    expect((await r.incr('k', 60_000)).current).toBe(1);
    expect((await r.incr('k', 60_000)).current).toBe(2); // counted locally, so the limit still bites
    expect((await r.incr('k', 60_000)).current).toBe(3);
    expect(primary.calls).toBe(1); // breaker open: no hammering of a struggling database
    expect(reasons).toEqual(['error', 'breaker', 'breaker']);
    await new Promise((x) => setTimeout(x, 160));
    await r.incr('k', 60_000);
    expect(primary.calls).toBe(2); // probes again after the breaker period
  });

  it('gives up on a hanging primary after the timeout instead of stalling the request', async () => {
    const reasons: string[] = [];
    const hanging: RateBackend = {
      incr: () => new Promise(() => undefined),
      purgeExpired: async () => 0,
    };
    const r = new ResilientRateBackend(hanging, new MemoryRateBackend(), {
      timeoutMs: 40,
      onFallback: (x) => reasons.push(x),
    });
    const t0 = Date.now();
    expect((await r.incr('k', 1000)).current).toBe(1);
    expect(Date.now() - t0).toBeLessThan(500);
    expect(reasons).toEqual(['timeout']);
  });
});

describe('fastifyRateStore adapter', () => {
  it('namespaces counters per route and passes the window through', async () => {
    const seen: Array<[string, number]> = [];
    const Store = fastifyRateStore({
      incr: async (bucket, windowMs) => (
        seen.push([bucket, windowMs]),
        { current: 1, ttl: windowMs }
      ),
      purgeExpired: async () => 0,
    });
    const root = new Store();
    const login = root.child({ routeInfo: { method: 'POST', url: '/v1/auth/login' } });
    const res = await new Promise((resolve) =>
      (login.incr as never as (k: string, cb: (e: unknown, r: unknown) => void, w: number) => void)(
        '1.2.3.4',
        (_e, r) => resolve(r),
        60_000,
      ),
    );
    expect(res).toEqual({ current: 1, ttl: 60_000 });
    (root.incr as never as (k: string, cb: () => void, w: number) => void)(
      '1.2.3.4',
      () => undefined,
      1000,
    );
    await new Promise((r) => setTimeout(r, 5));
    expect(seen).toEqual([
      ['POST /v1/auth/login|1.2.3.4', 60_000],
      ['global|1.2.3.4', 1000],
    ]);
  });

  it('reports backend errors to the plugin instead of throwing', async () => {
    const Store = fastifyRateStore({
      incr: async () => Promise.reject(new Error('boom')),
      purgeExpired: async () => 0,
    });
    const err = await new Promise((resolve) =>
      (new Store().incr as never as (k: string, cb: (e: unknown) => void, w: number) => void)(
        'k',
        (e) => resolve(e),
        1000,
      ),
    );
    expect((err as Error).message).toBe('boom');
  });
});

describe('RATE_LIMIT_STORE', () => {
  const prod = {
    NODE_ENV: 'production',
    LICENSE_KEY_PEPPER: 'x'.repeat(40),
    PSEUDONYM_KEY: 'x'.repeat(40),
    LICENSE_SIGNING_KEY_PEM: 'pem',
    DATABASE_URL: 'postgres://u:p@db/trust?sslmode=require',
    AUDIT_ANCHOR_DISABLED: 'true',
  };
  it('defaults to shared counters in production and per-process in development; validates the value', () => {
    expect(loadConfig(env(prod)).rateLimitStore).toBe('postgres');
    expect(loadConfig(env({})).rateLimitStore).toBe('memory');
    expect(loadConfig(env({ ...prod, RATE_LIMIT_STORE: 'memory' })).rateLimitStore).toBe('memory'); // explicit single-instance choice
    expect(
      loadConfig(
        env({
          PERSISTENCE: 'postgres',
          DATABASE_URL: 'postgres://u:p@db/t',
          RATE_LIMIT_STORE: 'postgres',
        }),
      ).rateLimitStore,
    ).toBe('postgres');
    expect(() => loadConfig(env({ RATE_LIMIT_STORE: 'redis' }))).toThrow(/RATE_LIMIT_STORE/);
    expect(() => loadConfig(env({ RATE_LIMIT_STORE: 'postgres' }))).toThrow(
      /requires PERSISTENCE=postgres/,
    );
  });
});
