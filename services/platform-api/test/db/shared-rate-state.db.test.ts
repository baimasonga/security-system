import { describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { generateEd25519 } from '@trust/crypto';
import { createSchemaPool } from '../../../../tests/support/pg.ts';
import { buildApp } from '../../src/app.ts';
import { loadConfig } from '../../src/config.ts';
import { createContainer, type Container } from '../../src/container.ts';
import { startMaintenance } from '../../src/maintenance.ts';
import type { PgPool } from '../../src/db/pg.ts';

const url = process.env['DATABASE_URL'];
const PW = 'correct horse battery staple';

describe.skipIf(!url)('abuse-control state shared across API instances (R-7)', () => {
  const pem = generateEd25519().privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const cfg = (over: Record<string, unknown> = {}) => ({
    ...loadConfig({
      NODE_ENV: 'test',
      PERSISTENCE: 'postgres',
      DATABASE_URL: url,
    } as NodeJS.ProcessEnv),
    signingKeyPem: pem,
    scrypt: { N: 1024, r: 8, p: 1 },
    rateLimits: { global: 100_000, login: 3, register: 3, challenge: 100_000, activate: 100_000 },
    ...over,
  });

  /** Several "API instances" = several containers and apps on ONE database (and nothing else in common). */
  async function instances(
    n: number,
    over: Record<string, unknown> = {},
    pool: PgPool = createSchemaPool(),
  ) {
    const cs: Container[] = [];
    const apps: FastifyInstance[] = [];
    for (let i = 0; i < n; i++) {
      const c = await createContainer(cfg(over), { pool });
      cs.push(c);
      apps.push(await buildApp(c));
    }
    return { pool, cs, apps };
  }
  const post = (app: FastifyInstance, path: string, body: unknown) =>
    app.inject({ method: 'POST', url: path, payload: body as object, remoteAddress: '10.0.0.7' });
  const bad = (app: FastifyInstance, email = 'x@example.test') =>
    post(app, '/v1/auth/login', { email, password: 'wrong-wrong-wrong' });

  it('postgres store: the per-IP limit is the TOTAL across instances; the memory store would allow each instance its own', async () => {
    const shared = await instances(2, { rateLimitStore: 'postgres' });
    const codes = [
      (await bad(shared.apps[0]!)).statusCode,
      (await bad(shared.apps[1]!)).statusCode,
      (await bad(shared.apps[0]!)).statusCode, // 3 = the limit
      (await bad(shared.apps[1]!)).statusCode, // 4th overall, from the OTHER instance
      (await bad(shared.apps[0]!)).statusCode,
    ];
    expect(codes).toEqual([401, 401, 401, 429, 429]);
    // another route has its own budget
    expect(
      (await post(shared.apps[1]!, '/v1/auth/register', { email: 'a@example.test', password: PW }))
        .statusCode,
    ).toBe(201);

    const local = await instances(2, { rateLimitStore: 'memory' });
    const lc = [];
    for (let i = 0; i < 3; i++) {
      lc.push((await bad(local.apps[0]!)).statusCode, (await bad(local.apps[1]!)).statusCode);
    }
    expect(lc).toEqual([401, 401, 401, 401, 401, 401]); // 6 attempts, no 429: each instance counts alone
    for (const a of [...shared.apps, ...local.apps]) await a.close();
  });

  it('different clients do not share a budget', async () => {
    const { apps } = await instances(2, { rateLimitStore: 'postgres' });
    for (let i = 0; i < 4; i++) await bad(apps[i % 2]!);
    const other = await apps[0]!.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: 'x@example.test', password: 'wrong-wrong-wrong' },
      remoteAddress: '10.0.0.99',
    });
    expect(other.statusCode).toBe(401);
    for (const a of apps) await a.close();
  });

  it('account lockout counts failures from every instance, and survives a restart', async () => {
    const pool = createSchemaPool();
    const { cs, apps } = await instances(
      2,
      {
        rateLimitStore: 'memory',
        rateLimits: {
          global: 100_000,
          login: 1000,
          register: 1000,
          challenge: 1000,
          activate: 1000,
        },
      },
      pool,
    );
    await cs[0]!.auth.register({ email: 'victim@example.test', password: PW });
    for (let i = 0; i < 3; i++) await bad(apps[0]!, 'victim@example.test');
    for (let i = 0; i < 2; i++) await bad(apps[1]!, 'victim@example.test');
    // five failures in total, but never five on one instance: the right password is refused on BOTH
    for (const a of apps) {
      const r = await post(a, '/v1/auth/login', { email: 'victim@example.test', password: PW });
      expect(r.statusCode).toBe(401);
    }
    // a brand new instance (restart) still knows
    const fresh = await instances(
      1,
      {
        rateLimitStore: 'memory',
        rateLimits: {
          global: 100_000,
          login: 1000,
          register: 1000,
          challenge: 1000,
          activate: 1000,
        },
      },
      pool,
    );
    expect(
      (await post(fresh.apps[0]!, '/v1/auth/login', { email: 'victim@example.test', password: PW }))
        .statusCode,
    ).toBe(401);
    // the stored key is a digest, not the address
    const keys = (await pool.query('SELECT key FROM login_failures')).rows.map(
      (r) => r.key as string,
    );
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^[0-9a-f]{64}$/);
    for (const a of [...apps, ...fresh.apps]) await a.close();
  });

  it('a database problem degrades the limiter to per-process counting; requests are still served and still limited', async () => {
    const { pool, cs, apps } = await instances(1, { rateLimitStore: 'postgres' });
    await pool.query('DROP TABLE rate_limits'); // every counter query now fails
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await bad(apps[0]!)).statusCode);
    expect(codes).toEqual([401, 401, 401, 429, 429]); // limit (3) still enforced locally
    const fb = Object.entries(cs[0]!.metrics.snapshot().counters).filter(([k]) =>
      k.startsWith('rate_limit_fallback_total'),
    );
    expect(fb.length).toBeGreaterThan(0);
    await apps[0]!.close();
  });

  it('maintenance deletes ended windows and stale failure counters, and leaves live ones', async () => {
    const { pool, cs, apps } = await instances(1, { rateLimitStore: 'postgres' });
    await bad(apps[0]!, 'someone@example.test'); // live window + a fresh failure counter
    await pool.query(
      "INSERT INTO rate_limits (bucket, count, window_end) VALUES ('old|1.1.1.1', 9, now() - interval '1 hour')",
    );
    const stale = 'a'.repeat(64);
    await pool.query(
      "INSERT INTO login_failures (key, count, updated_at) VALUES ($1, 2, now() - interval '3 days')",
      [stale],
    );
    await startMaintenance(cs[0]!).runOnce();
    const buckets = (await pool.query('SELECT bucket FROM rate_limits')).rows.map(
      (r) => r.bucket as string,
    );
    expect(buckets).not.toContain('old|1.1.1.1');
    expect(buckets.some((b) => b.includes('/v1/auth/login'))).toBe(true);
    const keys = (await pool.query('SELECT key FROM login_failures')).rows.map(
      (r) => r.key as string,
    );
    expect(keys).not.toContain(stale);
    expect(keys).toHaveLength(1);
    await apps[0]!.close();
  });
});
