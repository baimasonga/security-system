import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { MemorySecureStore, TrustPlatformClient } from '@trust/sdk-core';
import { makeEnv, DAY, PW, type Env } from '../../services/platform-api/test/harness.ts';
import { pgTestEnabled } from '../support/pg.ts';

/**
 * Database round-trip budget per device flow (PostgreSQL only). Each statement sent to the server is one
 * round trip; at 2 ms RTT every one costs ≥ 2 ms of latency and holds a pooled connection. These ceilings
 * are regression guards, set after the round-trip reduction (ADR-009, load-test report §3.11); baseline before it was 23 / 21 / 11.
 */
const BUDGET = { activate: 14, refresh: 10, validate: 5 };

describe.skipIf(!pgTestEnabled())('database round trips per device flow', () => {
  let env: Env;
  const log: string[] = [];
  let recording = false;
  const orig = pg.Client.prototype.query;

  beforeAll(async () => {
    (pg.Client.prototype as any).query = function (this: unknown, ...args: any[]) {
      if (recording)
        log.push(
          String(typeof args[0] === 'string' ? args[0] : args[0]?.text)
            .replace(/\s+/g, ' ')
            .slice(0, 110),
        );
      return (orig as any).apply(this, args);
    };
    env = await makeEnv();
    await env.app.listen({ host: '127.0.0.1', port: 0 });
  });
  afterAll(async () => {
    pg.Client.prototype.query = orig;
    await env.app.close();
  });

  it('stays within the per-flow statement budget (client calls: challenge + action)', async () => {
    const addr = env.app.server.address() as { port: number };
    const base = `http://127.0.0.1:${addr.port}`;
    const post = async (path: string, body: unknown, token?: string) => {
      const r = await fetch(base + path, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });
      return (await r.json()) as any;
    };
    const reg = await post('/v1/auth/register', { email: 'rt@example.test', password: PW });
    const token = (await post('/v1/auth/login', { email: 'rt@example.test', password: PW }))
      .token as string;
    const { licenseKey } = await env.provision(reg.personal_org.id);
    const trust = (await (await fetch(base + '/v1/keys/trust-bundle')).json()) as any;
    const client = new TrustPlatformClient({
      baseUrl: base,
      productCode: 'pdf-pro',
      trust,
      store: new MemorySecureStore(),
      now: env.clock.now,
    });

    const measure = async (name: keyof typeof BUDGET, fn: () => Promise<unknown>) => {
      log.length = 0;
      recording = true;
      await fn();
      recording = false;
      const stmts = log.filter((s) => !/^(BEGIN|COMMIT|ROLLBACK)/.test(s)).length;
      const all = log.length;
      if (process.env['TRACE'])
        process.stderr.write(
          `--- ${name}: ${all} statements (${stmts} excluding BEGIN/COMMIT)\n` +
            log.map((s, i) => `${i + 1}. ${s}`).join('\n') +
            '\n',
        );
      return all;
    };
    const counts = {
      activate: await measure('activate', () => client.activate(token, licenseKey)),
      refresh: await (env.clock.advance(16 * DAY), measure('refresh', () => client.refreshLease())),
      validate: await measure('validate', () => client.validateLicense()),
    };
    if (process.env['TRACE']) process.stderr.write('round trips ' + JSON.stringify(counts) + '\n');
    for (const k of Object.keys(BUDGET) as Array<keyof typeof BUDGET>)
      expect(counts[k], k).toBeLessThanOrEqual(BUDGET[k]);
  });
});
