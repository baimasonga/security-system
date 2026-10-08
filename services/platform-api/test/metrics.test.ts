import { afterEach, describe, expect, it } from 'vitest';
import { Metrics } from '../src/metrics.ts';
import { observer, setTransactionObserver, withTransaction, type PgPool } from '../src/db/pg.ts';
import { makeEnv, type Env } from './harness.ts';

describe('Metrics', () => {
  it('counts, buckets and reports upper-bound percentiles', () => {
    const m = new Metrics();
    m.inc('x_total', { a: 'b' });
    m.inc('x_total', { a: 'b' }, 2);
    for (const v of [1, 1, 1, 1, 1, 1, 1, 1, 1, 400]) m.observe('lat_ms', v, { route: '/r' });
    const s = m.snapshot();
    expect(s.counters['x_total{a="b"}']).toBe(3);
    const h = s.histograms['lat_ms{route="/r"}']!;
    expect(h).toMatchObject({ count: 10, p50_ms: 1, p95_ms: 500, max_ms: 400 });
    expect(h.p99_ms).toBeGreaterThanOrEqual(400); // never under-reports the tail
    m.close();
  });

  it('exposes process gauges and valid Prometheus text', () => {
    const m = new Metrics();
    m.inc('req_total', { route: '/a"b\n' });
    m.observe('lat_ms', 3, { route: '/a' });
    const text = m.prometheus();
    expect(text).toMatch(/^trust_process_rss_bytes \d+/m);
    expect(text).toContain('trust_lat_ms_bucket{route="/a",le="5"} 1');
    expect(text).toContain('trust_lat_ms_bucket{route="/a",le="+Inf"} 1');
    expect(text).toContain('trust_lat_ms_count{route="/a"} 1');
    expect(text).not.toMatch(/\n[^\n]*"\n[^\n]*"/); // label values cannot break lines
    m.close();
  });
});

describe('transaction observer (retry / exhaustion visibility)', () => {
  const pool = (failures: number) => {
    let n = 0;
    return {
      async connect() {
        return {
          async query(t: string) {
            if (t === 'BEGIN') n++;
            return { rows: [], rowCount: 0 };
          },
          release() {},
        };
      },
      attempts: () => n,
      failures,
    } as unknown as PgPool;
  };
  afterEach(() => setTransactionObserver({}));

  it('reports ok / retry / exhausted outcomes with attempt counts', async () => {
    const events: string[] = [];
    setTransactionObserver({
      onTransaction: (e) => events.push(`${e.outcome}:${e.attempts}`),
      onRetry: (e) => events.push(`retry:${e.code}`),
    });
    let runs = 0;
    await withTransaction(
      pool(0),
      async () => {
        if (++runs < 3) throw Object.assign(new Error('x'), { code: '40P01' });
      },
      { sleep: async () => {} },
    );
    await expect(
      withTransaction(
        pool(0),
        async () => {
          throw Object.assign(new Error('x'), { code: '40001' });
        },
        { sleep: async () => {}, maxAttempts: 2 },
      ),
    ).rejects.toBeDefined();
    await expect(
      withTransaction(
        pool(0),
        async () => {
          throw new Error('domain');
        },
        { sleep: async () => {} },
      ),
    ).rejects.toThrow();
    expect(events).toEqual([
      'retry:40P01',
      'retry:40P01',
      'ok:3',
      'retry:40001',
      'exhausted:2',
      'error:1',
    ]);
    expect(observer.onTransaction).toBeDefined();
  });
});

describe('GET /v1/admin/metrics', () => {
  let env: Env;
  afterEach(async () => env?.app.close());

  it('is operator-only', async () => {
    env = await makeEnv();
    const user = await env.register('u@example.test');
    expect((await env.call('GET', '/v1/admin/metrics')).status).toBe(401);
    expect((await env.call('GET', '/v1/admin/metrics', { token: user.token })).status).toBe(403);
  });

  it('records request metrics by route template only — no ids, emails or tokens in labels', async () => {
    env = await makeEnv();
    const u = await env.register('secret-person@example.test');
    await env.call('GET', `/v1/organizations/${u.orgId}`, { token: u.token });
    await env.call('GET', '/v1/nope');
    const op = await env.operatorToken();
    const snap = (await env.call('GET', '/v1/admin/metrics', { token: op })).body;
    const keys = Object.keys(snap.counters).join('\n') + Object.keys(snap.histograms).join('\n');
    expect(keys).toContain('route="/v1/organizations/:orgId"');
    expect(keys).toContain('route="unmatched"');
    expect(keys).not.toContain(u.orgId);
    expect(keys).not.toMatch(/secret-person|sess_|LK-/);
    const prom = await env.app.inject({
      method: 'GET',
      url: '/v1/admin/metrics?format=prometheus',
      headers: { authorization: `Bearer ${op}` },
    });
    expect(prom.headers['content-type']).toContain('text/plain');
    expect(prom.body).toContain('trust_http_requests_total{');
    expect((await env.call('GET', '/v1/admin/metrics?format=xml', { token: op })).status).toBe(400);
  });
});
