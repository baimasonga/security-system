import type { PgPool } from './db/pg.ts';

// R-7: request counters for the HTTP rate limiter that every API instance can share.
//
// The limiter (@fastify/rate-limit) keeps fixed windows. A `RateBackend` is the part that stores them:
//  - MemoryRateBackend: per process (development, single instance, and the degraded-mode fallback);
//  - PgRateBackend:     one UPSERT per limited request into an UNLOGGED table, windows timed by the database clock;
//  - ResilientRateBackend: PostgreSQL first, memory when PostgreSQL is slow or failing, so a database problem
//    never makes the limiter weaker than it was before this change, and never blocks requests for long.

export interface RateWindow {
  /** Requests counted in the current window, including this one. */
  current: number;
  /** Milliseconds until the window ends. */
  ttl: number;
}

export interface RateBackend {
  incr(bucket: string, windowMs: number): Promise<RateWindow>;
  /** Deletes up to `limit` windows that have ended. Returns the number deleted. */
  purgeExpired(limit?: number): Promise<number>;
}

const MAX_BUCKET = 300;
const bounded = (b: string) => (b.length > MAX_BUCKET ? b.slice(0, MAX_BUCKET) : b);

export class MemoryRateBackend implements RateBackend {
  readonly #w = new Map<string, { current: number; end: number }>();
  readonly #max: number;
  readonly #now: () => number;
  constructor(opts: { maxBuckets?: number; now?: () => number } = {}) {
    this.#max = opts.maxBuckets ?? 50_000;
    this.#now = opts.now ?? Date.now;
  }
  async incr(bucket: string, windowMs: number): Promise<RateWindow> {
    const key = bounded(bucket);
    const now = this.#now();
    let w = this.#w.get(key);
    if (!w || w.end <= now) {
      if (!w && this.#w.size >= this.#max) this.#evict(now);
      w = { current: 0, end: now + windowMs };
    }
    w.current++;
    this.#w.set(key, w);
    return { current: w.current, ttl: w.end - now };
  }
  #evict(now: number): void {
    for (const [k, w] of this.#w) if (w.end <= now) this.#w.delete(k);
    // Still full of live windows: drop the oldest insertions. Bounded memory beats unbounded growth under attack.
    for (const k of this.#w.keys()) {
      if (this.#w.size < this.#max) break;
      this.#w.delete(k);
    }
  }
  async purgeExpired(): Promise<number> {
    const now = this.#now();
    let n = 0;
    for (const [k, w] of this.#w)
      if (w.end <= now) {
        this.#w.delete(k);
        n++;
      }
    return n;
  }
  get size(): number {
    return this.#w.size;
  }
}

export class PgRateBackend implements RateBackend {
  readonly #pool: PgPool;
  constructor(pool: PgPool) {
    this.#pool = pool;
  }
  async incr(bucket: string, windowMs: number): Promise<RateWindow> {
    // One statement. now() is the database's transaction time, identical for every instance.
    const r = await this.#pool.query(
      `INSERT INTO rate_limits AS r (bucket, count, window_end)
       VALUES ($1, 1, now() + ($2 * interval '1 millisecond'))
       ON CONFLICT (bucket) DO UPDATE
          SET count      = CASE WHEN r.window_end <= now() THEN 1 ELSE r.count + 1 END,
              window_end = CASE WHEN r.window_end <= now() THEN now() + ($2 * interval '1 millisecond') ELSE r.window_end END
       RETURNING count, (extract(epoch FROM (window_end - now())) * 1000)::bigint AS ttl_ms`,
      [bounded(bucket), windowMs],
    );
    const row = r.rows[0]!;
    return { current: row.count as number, ttl: Number(row.ttl_ms) };
  }
  async purgeExpired(limit = 5000): Promise<number> {
    const r = await this.#pool.query(
      'DELETE FROM rate_limits WHERE bucket IN (SELECT bucket FROM rate_limits WHERE window_end < now() LIMIT $1)',
      [limit],
    );
    return r.rowCount ?? 0;
  }
}

export class ResilientRateBackend implements RateBackend {
  readonly #primary: RateBackend;
  readonly #fallback: RateBackend;
  readonly #timeoutMs: number;
  readonly #breakerMs: number;
  readonly #onFallback: (reason: 'error' | 'timeout' | 'breaker') => void;
  #openUntil = 0;

  constructor(
    primary: RateBackend,
    fallback: RateBackend,
    opts: {
      timeoutMs?: number;
      breakerMs?: number;
      onFallback?: (r: 'error' | 'timeout' | 'breaker') => void;
    } = {},
  ) {
    this.#primary = primary;
    this.#fallback = fallback;
    this.#timeoutMs = opts.timeoutMs ?? 300;
    this.#breakerMs = opts.breakerMs ?? 5_000;
    this.#onFallback = opts.onFallback ?? (() => undefined);
  }

  async incr(bucket: string, windowMs: number): Promise<RateWindow> {
    // Count every request locally, including those served by the primary.
    const local = await this.#fallback.incr(bucket, windowMs);
    if (Date.now() < this.#openUntil) {
      this.#onFallback('breaker');
      return local;
    }
    let timer: NodeJS.Timeout | undefined;
    try {
      const shared = await Promise.race([
        this.#primary.incr(bucket, windowMs),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('timeout')), this.#timeoutMs);
        }),
      ]);
      // Independent window boundaries can differ. Keep the stricter local/shared result.
      return {
        current: Math.max(shared.current, local.current),
        ttl: Math.max(shared.ttl, local.ttl),
      };
    } catch (e) {
      // Stop asking a struggling database for a few seconds; count locally meanwhile.
      this.#openUntil = Date.now() + this.#breakerMs;
      this.#onFallback((e as Error).message === 'timeout' ? 'timeout' : 'error');
      return local;
    } finally {
      clearTimeout(timer);
    }
  }

  async purgeExpired(limit?: number): Promise<number> {
    return (await this.#primary.purgeExpired(limit)) + (await this.#fallback.purgeExpired(limit));
  }
}

/**
 * Adapter for @fastify/rate-limit's `store` option. The plugin creates one store per route (`child`), so every
 * route has its own counters, as with the default store.
 */
export function fastifyRateStore(backend: RateBackend) {
  class Store {
    readonly #ns: string;
    constructor(_params?: unknown, ns = 'global') {
      this.#ns = ns;
    }
    incr(key: string, cb: (err: Error | null, res?: RateWindow) => void, timeWindow: number): void {
      backend.incr(`${this.#ns}|${key}`, timeWindow).then(
        (r) => cb(null, r),
        (e: unknown) => cb(e as Error),
      );
    }
    child(routeOptions: { routeInfo: { method: string | string[]; url: string } }): Store {
      const m = routeOptions.routeInfo.method;
      return new Store(
        undefined,
        `${Array.isArray(m) ? m.join(',') : m} ${routeOptions.routeInfo.url}`,
      );
    }
  }
  return Store;
}
