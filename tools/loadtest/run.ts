// Load / soak test driver. Run under an ephemeral PostgreSQL:
//   PG_FSYNC=on node tools/with-postgres.mjs node tools/loadtest/run.ts --scenario <name> [--out file.json] [opts]
// Scenarios: quota-ramp | audit-micro | activate-ramp | refresh-ramp | hot-license | herd | soak | pool-sweep
import { writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import pg from 'pg';
import { PgAuditLog } from '../../services/platform-api/src/db/pg-audit-log.ts';
import {
  Balancer,
  type Http,
  type Requester,
  loadavg,
  openLoop,
  postgresCpuS,
  percentiles,
  procStat,
  round,
  type OpResult,
  type StepReport,
} from './lib.ts';
import { startDelayProxy } from './delayproxy.ts';
import { VDev, seedWorld, startServer, type Server, type SeedUser } from './world.ts';

// `--key value` pairs and bare `--flag`s (a flag is any `--x` not followed by a value).
const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i++) {
  const tok = process.argv[i]!;
  if (!tok.startsWith('--')) throw new Error(`unexpected argument "${tok}"`);
  const next = process.argv[i + 1];
  if (next === undefined || next.startsWith('--')) args.set(tok.slice(2), '');
  else {
    args.set(tok.slice(2), next);
    i++;
  }
}
const num = (k: string, d: number) => (args.has(k) ? Number(args.get(k)) : d);
const list = (k: string, d: number[]) => (args.has(k) ? args.get(k)!.split(',').map(Number) : d);
const dbUrl = process.env['DATABASE_URL']!;
if (!dbUrl) throw new Error('DATABASE_URL required (run via tools/with-postgres.mjs)');

/** Extra server environment, e.g. --srvenv CHALLENGE_RETENTION_SECONDS=180,MAINTENANCE_INTERVAL_SECONDS=30 */
const srvEnv: Record<string, string> = Object.fromEntries(
  (args.get('srvenv') ?? '')
    .split(',')
    .filter(Boolean)
    .map((kv) => [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)] as [string, string]),
);
const POOL = num('pool', 10);
const PORT = num('port', 18200);
const result: Record<string, unknown> = {
  scenario: args.get('scenario'),
  startedAt: new Date().toISOString(),
  cpus: 4,
  fsync: process.env['PG_FSYNC'] === 'on',
  pool: POOL,
  logLevel: args.get('log') ?? 'info',
};
let dirty = 0; // steps that saw errors or generator-side drops (for --assert-clean)
const log = (...a: unknown[]) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---- observation helpers ----------------------------------------------------------------------
const dbc = new pg.Client({ connectionString: dbUrl });
async function dbStats() {
  const q = async (sql: string) => (await dbc.query(sql)).rows;
  // Sequential on purpose: one client runs one statement at a time.
  const [a] = await q(
    "SELECT count(*)::int AS conns, count(*) FILTER (WHERE state='active')::int AS active, count(*) FILTER (WHERE wait_event_type='Lock')::int AS lock_waiting FROM pg_stat_activity WHERE datname = current_database()",
  );
  const [d] = await q(
    'SELECT deadlocks::int, xact_commit::bigint::int AS commits, xact_rollback::bigint::int AS rollbacks FROM pg_stat_database WHERE datname = current_database()',
  );
  const sizes = await q(
    "SELECT relname, (pg_total_relation_size(c.oid)/1048576.0)::numeric(10,2)::float AS mb, COALESCE((SELECT n_live_tup FROM pg_stat_user_tables t WHERE t.relid = c.oid), 0)::int AS rows FROM pg_class c WHERE relname IN ('audit_events','leases','challenges','activations','devices') AND relkind='r'",
  );
  return {
    ...a,
    ...d,
    tables: Object.fromEntries(sizes.map((s: any) => [s.relname, { mb: s.mb, rows: s.rows }])),
  };
}
/** Admin metrics from EVERY instance, merged (counters/histogram totals summed, gauges summed or maxed). */
async function serverMetrics(c: Ctx): Promise<any> {
  const all = await Promise.all(
    c.admins.map(
      async (h) => (await h.request('GET', '/v1/admin/metrics', undefined, c.operatorToken)).body,
    ),
  );
  if (all.length === 1) return all[0];
  const out: any = { counters: {}, gauges: {}, histograms: {} };
  for (const m of all) {
    for (const [k, v] of Object.entries<number>(m.counters))
      out.counters[k] = (out.counters[k] ?? 0) + v;
    for (const [k, v] of Object.entries<number>(m.gauges))
      out.gauges[k] =
        k.includes('event_loop') || k.includes('rss')
          ? Math.max(out.gauges[k] ?? 0, v)
          : (out.gauges[k] ?? 0) + v;
    for (const [k, h] of Object.entries<any>(m.histograms)) {
      const o = (out.histograms[k] ??= { count: 0, sum_ms: 0, max_ms: 0, p99_ms: 0 });
      o.count += h.count;
      o.sum_ms += h.sum_ms;
      o.max_ms = Math.max(o.max_ms, h.max_ms);
      o.p99_ms = Math.max(o.p99_ms, h.p99_ms);
    }
  }
  return out;
}
/** Summed CPU seconds / RSS over all server processes. */
function procSum(c: Ctx) {
  const ps = c.servers.map((s) => procStat(s.pid)!);
  return {
    cpuS: ps.reduce((a, p) => a + p.cpuS, 0),
    rssMb: round(
      ps.reduce((a, p) => a + p.rssMb, 0),
      1,
    ),
    threads: ps.reduce((a, p) => a + p.threads, 0),
  };
}
const cnt = (m: any, prefix: string) =>
  Object.entries(m.counters)
    .filter(([k]) => k.startsWith(prefix))
    .reduce((s, [, v]) => s + (v as number), 0);
function serverDelta(before: any, after: any) {
  const hist = (m: any, k: string) => m.histograms[k] ?? { count: 0, sum_ms: 0 };
  const dc = hist(after, 'audit_lock_wait_ms').count - hist(before, 'audit_lock_wait_ms').count;
  const ds = hist(after, 'audit_lock_wait_ms').sum_ms - hist(before, 'audit_lock_wait_ms').sum_ms;
  return {
    txRetries: cnt(after, 'db_tx_retries_total') - cnt(before, 'db_tx_retries_total'),
    txExhausted:
      (after.counters['db_tx_total{outcome="exhausted"}'] ?? 0) -
      (before.counters['db_tx_total{outcome="exhausted"}'] ?? 0),
    auditAppends: dc,
    auditLockWaitMeanMs: dc ? round(ds / dc, 2) : 0,
    auditLockWaitP99MsCumulative: after.histograms['audit_lock_wait_ms']?.p99_ms ?? 0,
    maintenanceRuns: cnt(after, 'maintenance_runs_total') - cnt(before, 'maintenance_runs_total'),
    maintenanceDeleted:
      cnt(after, 'maintenance_deleted_total') - cnt(before, 'maintenance_deleted_total'),
    eventLoopP99Ms: after.gauges['process_event_loop_delay_p99_ms'],
    poolWaiting: after.gauges['db_pool_waiting'],
    poolTotal: after.gauges['db_pool_total'],
  };
}

interface Ctx {
  servers: Server[];
  admins: Http[];
  http: Requester;
  users: SeedUser[];
  operatorToken: string;
  extras: Record<string, SeedUser>;
}
async function withServer<T>(
  users: number,
  deviceLimit: number,
  pool: number,
  fn: (c: Ctx) => Promise<T>,
  extraOrgs?: Array<{ name: string; deviceLimit: number }>,
): Promise<T> {
  log(`seeding ${users} users…`);
  const t0 = performance.now();
  const w = await seedWorld(dbUrl, { users, deviceLimit, ...(extraOrgs ? { extraOrgs } : {}) });
  log(`seeded in ${round((performance.now() - t0) / 1000, 1)}s`);
  const instances = num('instances', 1);
  const servers: Server[] = [];
  for (let i = 0; i < instances; i++)
    servers.push(
      await startServer(dbUrl, {
        port: PORT + i,
        pool,
        logLevel: args.get('log') ?? 'info',
        extraEnv: srvEnv,
      }),
    );
  const http = new Balancer(
    servers.map((s) => s.base),
    256,
  );
  try {
    return await fn({
      servers,
      admins: http.members,
      http,
      users: w.users,
      operatorToken: w.operatorToken,
      extras: w.extras,
    });
  } finally {
    http.destroy();
    for (const s of servers) await s.stop();
  }
}

/** Runs one measured step and attaches server-side + system observations. */
async function step(
  c: Ctx,
  name: string,
  rps: number,
  durationS: number,
  op: (i: number) => Promise<OpResult>,
  maxInFlight = 400,
) {
  const m0 = await serverMetrics(c);
  const p0 = procSum(c);
  const lg0 = process.cpuUsage();
  const pg0 = postgresCpuS();
  const d0 = await dbStats();
  let poolWaitMax = 0,
    connsMax = 0,
    lockWaitMax = 0;
  const rep: StepReport = await openLoop({
    name,
    rps,
    durationS,
    maxInFlight,
    op,
    onTick: async () => {
      const s = await dbStats();
      connsMax = Math.max(connsMax, s.conns);
      lockWaitMax = Math.max(lockWaitMax, s.lock_waiting);
      const m = await serverMetrics(c);
      poolWaitMax = Math.max(poolWaitMax, m.gauges['db_pool_waiting'] ?? 0);
    },
  });
  const m1 = await serverMetrics(c);
  const p1 = procSum(c);
  const lg = process.cpuUsage(lg0);
  const pgCpuPct = round(((postgresCpuS() - pg0) / rep.durationS) * 100, 0);
  const d1 = await dbStats();
  const out = {
    ...rep,
    windows: undefined,
    server: {
      ...serverDelta(m0, m1),
      cpuPct: round(((p1.cpuS - p0.cpuS) / rep.durationS) * 100, 0),
      rssMb: p1.rssMb,
      poolWaitingMax: poolWaitMax,
    },
    db: {
      connsMax,
      lockWaitingMax: lockWaitMax,
      deadlocks: d1.deadlocks - d0.deadlocks,
      commits: d1.commits - d0.commits,
      rollbacks: d1.rollbacks - d0.rollbacks,
    },
    // If the generator itself is near 100% of one core, the numbers are generator-bound, not server-bound.
    postgresCpuPct: pgCpuPct,
    loadgenCpuPct: round(((lg.user + lg.system) / 1e6 / rep.durationS) * 100, 0),
    loadavg: loadavg(),
  };
  if (Object.keys(rep.errors).length > 0 || rep.dropped > 0) dirty++;
  const errs =
    Object.entries(rep.errors)
      .map(([k, v]) => `${k}=${v}`)
      .join(' ') || '-';
  log(
    `${name.padEnd(22)} target ${String(rps).padStart(4)} rps → ${String(rep.achievedRps).padStart(6)} rps  p50 ${rep.latencyMs['p50']} p95 ${rep.latencyMs['p95']} p99 ${rep.latencyMs['p99']} max ${rep.maxMs}ms  dropped ${rep.dropped}  err: ${errs}  srvCPU ${out.server.cpuPct}% genCPU ${out.loadgenCpuPct}% pgCPU ${out.postgresCpuPct}%  retries ${out.server.txRetries} lockwait ${out.server.auditLockWaitMeanMs}ms  deadlocks ${out.db.deadlocks}`,
  );
  return out;
}
const saturated = (r: any) =>
  r.latencyMs.p99 > 2000 ||
  r.completed === 0 ||
  Object.values<number>(r.errors).reduce((a, b) => a + b, 0) / r.completed > 0.01 ||
  r.dropped > 0;

// ---- scenarios --------------------------------------------------------------------------------
async function activateMany(c: Ctx, devs: VDev[], concurrency: number) {
  let n = 0,
    fail = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: concurrency }, async () => {
      for (;;) {
        const i = n++;
        if (i >= devs.length) return;
        const r = await devs[i]!.activate(c.http).catch(() => ({ ok: false, code: 'client' }));
        if (!r.ok) fail++;
      }
    }),
  );
  return {
    seconds: round((performance.now() - t0) / 1000, 1),
    perSecond: round(devs.length / ((performance.now() - t0) / 1000), 1),
    failed: fail,
  };
}

const scenarios: Record<string, () => Promise<void>> = {
  async 'quota-ramp'() {
    const limit = num('quota-limit', 1000);
    if (!Number.isInteger(limit) || limit < 1 || limit > 2 ** 40)
      throw new Error('invalid quota limit');
    await withServer(num('users', 20), 3, POOL, async (c) => {
      const user = c.users[0]!;
      const path = `/v1/organizations/${user.orgId}/licenses/${user.licenseId}/usage`;
      const license = await c.http.request(
        'GET',
        `/v1/organizations/${user.orgId}/licenses/${user.licenseId}`,
        undefined,
        user.token,
      );
      const configured = await c.http.request(
        'PATCH',
        `/v1/admin/plans/${license.body.plan_id}`,
        {
          entitlements: { pdf_editing: true, ocr_pages_monthly: limit },
          reason: 'Quota load verification',
        },
        c.operatorToken,
      );
      if (configured.status !== 200) throw new Error('quota plan configuration failed');
      const operations = new Set<string>(),
        receipts = new Set<string>();
      const frequencies = new Map<string, number>(),
        acceptedOperations = new Set<string>();
      let accepted = 0,
        exhausted = 0,
        offset = 0;
      const rows = [];
      for (const rps of list('rps', [20])) {
        const row = await step(
          c,
          'quota consume/retry on one license',
          rps,
          num('seconds', 4),
          async (i) => {
            const key = `load-quota-operation-${Math.floor((offset + i) / 2)}`;
            operations.add(key);
            frequencies.set(key, (frequencies.get(key) ?? 0) + 1);
            const response = await c.http.request(
              'POST',
              path,
              { entitlement: 'ocr_pages_monthly', units: 1, idempotency_key: key },
              user.token,
            );
            if (response.status === 200) {
              accepted++;
              acceptedOperations.add(key);
              receipts.add(response.body.id);
              return { ok: true, code: 'ok' };
            }
            if (response.status === 409 && response.body.message === 'monthly quota exhausted') {
              exhausted++;
              return { ok: true, code: 'ok' };
            }
            return { ok: false, code: String(response.status) };
          },
        );
        rows.push(row);
        offset += row.launched;
      }
      const usage = await c.http.request('GET', path, undefined, user.token);
      const expected = Math.min(limit, operations.size);
      if (
        usage.status !== 200 ||
        usage.body.items[0]?.used !== expected ||
        receipts.size !== expected
      )
        throw new Error('quota consumption invariant failed');
      const expectedAccepted = [...acceptedOperations].reduce(
        (total, key) => total + frequencies.get(key)!,
        0,
      );
      const attempts = [...frequencies.values()].reduce((a, b) => a + b, 0);
      if (
        accepted !== expectedAccepted ||
        exhausted !== attempts - expectedAccepted ||
        rows.reduce((sum, row) => sum + row.server.auditAppends, 0) !== expected
      )
        throw new Error('quota retry/audit invariant failed');
      result['rows'] = rows;
      result['quota'] = {
        limit,
        operations: operations.size,
        uniqueReceipts: receipts.size,
        accepted,
        exhausted,
        used: usage.body.items[0].used,
        remaining: usage.body.items[0].remaining,
      };
      const audit = await c.http.request(
        'GET',
        '/v1/admin/audit/verify',
        undefined,
        c.operatorToken,
      );
      if (audit.status !== 200 || !audit.body.ok)
        throw new Error('quota audit verification failed');
      result['auditVerified'] = true;
      result['final'] = await dbStats();
    });
  },

  /**
   * Same workload with a fixed network round trip between the API and PostgreSQL. Database round trips
   * dominate per-request latency and the audit-chain lock is held across several of them plus the commit,
   * so distance matters far more than on loopback.
   */
  async 'latency-sweep'() {
    const w = await seedWorld(dbUrl, { users: num('users', 600), deviceLimit: 10 });
    const target = Number(new URL(dbUrl).port);
    const rows: unknown[] = [];
    for (const oneWay of list('oneway', [0, 1, 2])) {
      const proxy = await startDelayProxy(target, oneWay);
      const proxied = new URL(dbUrl);
      proxied.port = String(proxy.port);
      const srv = await startServer(proxied.toString(), {
        port: PORT,
        pool: POOL,
        logLevel: 'info',
        extraEnv: srvEnv,
      });
      const http = new Balancer([srv.base], 256);
      const c: Ctx = {
        servers: [srv],
        admins: http.members,
        http,
        users: w.users,
        operatorToken: w.operatorToken,
        extras: {},
      };
      try {
        const devs = w.users.map((u) => new VDev(u));
        await activateMany(c, devs, 32);
        for (const rps of list('rps', [25, 50, 100, 200])) {
          const r = await step(c, `refresh rtt=${oneWay * 2}ms`, rps, num('seconds', 12), (i) =>
            devs[i % devs.length]!.deviceCall(c.http, 'refresh'),
          );
          rows.push({ rttMs: oneWay * 2, ...r });
          if (saturated(r)) break;
        }
      } finally {
        http.destroy();
        await srv.stop();
        await proxy.close();
      }
    }
    result['rows'] = rows;
  },

  /** Cost of the retention DELETE on a big table, with and without the expires_at index (migration 0002). */
  async 'purge-micro'() {
    await seedWorld(dbUrl, { users: 1, deviceLimit: 1 });
    const rowsN = num('rows', 500_000);
    await dbc.query('CREATE TABLE challenges_noindex (LIKE challenges INCLUDING DEFAULTS)'); // same columns, no indexes
    for (const t of ['challenges', 'challenges_noindex']) {
      await dbc.query(
        `INSERT INTO ${t} (nonce_hash, purpose, installation_id, expires_at, consumed_at)
         SELECT $1 || g, 'refresh', 'inst_x', now() + interval '1 day' + (g || ' ms')::interval, now() FROM generate_series(1, $2::int) g`,
        [t, rowsN],
      );
      await dbc.query(`ANALYZE ${t}`);
    }
    const out: Record<string, unknown> = { rows: rowsN };
    for (const [label, t] of [
      ['indexed (0002)', 'challenges'],
      ['no index (before)', 'challenges_noindex'],
    ] as const) {
      const lat: number[] = [];
      for (let i = 0; i < 40; i++) {
        const s0 = performance.now();
        // nothing is expired: this is the steady-state cost of "is there anything to delete?"
        await dbc.query(
          `DELETE FROM ${t} WHERE ctid IN (SELECT ctid FROM ${t} WHERE expires_at < now() - interval '1 hour' LIMIT 5000)`,
        );
        lat.push(performance.now() - s0);
      }
      out[label] = {
        meanMs: round(lat.reduce((a, b) => a + b, 0) / lat.length, 2),
        ...percentiles(lat, [50, 99]),
      };
      log(label, JSON.stringify(out[label]));
    }
    result['purge'] = out;
  },

  async 'audit-micro'() {
    await seedWorld(dbUrl, { users: 1, deviceLimit: 1 });
    const rows: unknown[] = [];
    const target = Number(new URL(dbUrl).port);
    for (const oneWay of list('oneway', [0]))
      for (const conc of list('conc', [1, 2, 4, 8, 16, 32, 64])) {
        // oneWay > 0 inserts a delaying proxy (round trip ≈ 2 × oneWay ms) between this process and PostgreSQL
        const proxy = oneWay > 0 ? await startDelayProxy(target, oneWay) : undefined;
        const url = new URL(dbUrl);
        if (proxy) url.port = String(proxy.port);
        const pool = new pg.Pool({ connectionString: url.toString(), max: conc });
        const orgs = num('orgs', 0); // 0 = org-less events (all on the `system` chain = the old global-chain behaviour)
        const log_ = new PgAuditLog(pool, { now: () => new Date() }, { shards: num('shards', 1) });
        const lat: number[] = [];
        let stop = false,
          n = 0;
        setTimeout(() => (stop = true), num('seconds', 6) * 1000);
        const t0 = performance.now();
        await Promise.all(
          Array.from({ length: conc }, async (_, w) => {
            let k = 0;
            while (!stop) {
              const s = performance.now();
              await log_.append({
                actor: { type: 'system' },
                action: 'bench.event',
                ...(orgs > 0 ? { orgId: `org_bench_${w % orgs}` } : {}),
                target: { type: 'device', id: `dev_${w}_${k++ % 64}` },
                metadata: { n: 1 },
              });
              lat.push(performance.now() - s);
              n++;
            }
          }),
        );
        const secs = (performance.now() - t0) / 1000;
        const row = {
          rttMs: oneWay * 2,
          orgs,
          shards: num('shards', 1),
          concurrency: conc,
          eventsPerSec: round(n / secs, 0),
          latencyMs: percentiles(lat, [50, 99]),
        };
        rows.push(row);
        log(JSON.stringify(row));
        await pool.end();
        await proxy?.close();
      }
    const v0 = performance.now();
    const verify = await new PgAuditLog(new pg.Pool({ connectionString: dbUrl }), {
      now: () => new Date(),
    }).verifyChain();
    const { heads: _heads, ...verifySummary } = verify as typeof verify & { heads?: unknown };
    void _heads;
    result['verifyChain'] = { ...verifySummary, ms: round(performance.now() - v0, 0) };
    result['rows'] = rows;
  },

  async 'activate-ramp'() {
    const steps = list('rps', [25, 50, 100, 150, 200, 300, 400]);
    await withServer(num('users', 2000), 1000, POOL, async (c) => {
      const rows: unknown[] = [];
      let k = 0;
      for (const rps of steps) {
        const r = await step(c, 'activate', rps, num('seconds', 15), (i) =>
          new VDev(c.users[(k + i) % c.users.length]!).activate(c.http),
        );
        k += Math.floor(rps * num('seconds', 15));
        rows.push(r);
        if (saturated(r)) {
          log('saturated; stopping ramp');
          break;
        }
      }
      result['rows'] = rows;
      result['final'] = await dbStats();
    });
  },

  async 'refresh-ramp'() {
    const steps = list('rps', [50, 100, 200, 300, 400, 600, 800]);
    await withServer(num('users', 2000), 10, POOL, async (c) => {
      const devs = c.users.map((u) => new VDev(u));
      result['preActivation'] = await activateMany(c, devs, 32);
      log('pre-activation', JSON.stringify(result['preActivation']));
      const rows: unknown[] = [];
      for (const rps of steps) {
        const r = await step(c, 'refresh', rps, num('seconds', 15), (i) =>
          devs[i % devs.length]!.deviceCall(c.http, 'refresh'),
        );
        rows.push(r);
        if (saturated(r)) {
          log('saturated; stopping ramp');
          break;
        }
      }
      result['rows'] = rows;
      result['final'] = await dbStats();
    });
  },

  async 'hot-license'() {
    const steps = list('rps', [25, 50, 100, 200, 400]);
    await withServer(
      num('users', 500),
      10,
      POOL,
      async (c) => {
        const big = c.extras['enterprise']!;
        const hot = Array.from({ length: num('devices', 300) }, () => new VDev(big));
        result['preActivation'] = await activateMany(c, hot, 32);
        const spread = c.users.map((u) => new VDev(u));
        await activateMany(c, spread, 32);
        const rows: unknown[] = [];
        for (const rps of steps) {
          const a = await step(c, 'refresh/ONE license', rps, num('seconds', 15), (i) =>
            hot[i % hot.length]!.deviceCall(c.http, 'refresh'),
          );
          const b = await step(c, 'refresh/spread', rps, num('seconds', 15), (i) =>
            spread[i % spread.length]!.deviceCall(c.http, 'refresh'),
          );
          rows.push({ rps, oneLicense: a, spread: b });
          if (saturated(a) && saturated(b)) break;
        }
        result['rows'] = rows;
      },
      [{ name: 'enterprise', deviceLimit: 5000 }],
    );
  },

  async herd() {
    await withServer(
      50,
      10,
      POOL,
      async (c) => {
        const lim = c.extras['limited']!;
        const n = num('devices', 300);
        const devs = Array.from({ length: n }, () => new VDev(lim));
        const m0 = await serverMetrics(c);
        const d0 = await dbStats();
        const t0 = performance.now();
        const codes: Record<string, number> = {};
        const lat: number[] = [];
        await Promise.all(
          devs.map(async (d) => {
            const s = performance.now();
            const r = await d.activate(c.http).catch(() => ({ ok: false, code: 'client' }));
            lat.push(performance.now() - s);
            codes[r.code] = (codes[r.code] ?? 0) + 1;
          }),
        );
        const m1 = await serverMetrics(c);
        const d1 = await dbStats();
        result['herd'] = {
          devices: n,
          limit: 5,
          wallMs: round(performance.now() - t0, 0),
          outcomes: codes,
          latencyMs: percentiles(lat),
          server: serverDelta(m0, m1),
          deadlocks: d1.deadlocks - d0.deadlocks,
        };
        log(JSON.stringify(result['herd']));
      },
      [{ name: 'limited', deviceLimit: 5 }],
    );
  },

  async soak() {
    const rps = num('rps', 60),
      minutes = num('minutes', 15),
      windowS = 60;
    await withServer(num('users', 2000), 1000, POOL, async (c) => {
      const active: VDev[] = c.users.slice(0, 1000).map((u) => new VDev(u));
      await activateMany(c, active, 32);
      const timeline: unknown[] = [];
      const baseline = {
        db: await dbStats(),
        proc: procSum(c),
        m: await serverMetrics(c),
      };
      const mixed = async (): Promise<OpResult> => {
        const x = Math.random();
        if (x < 0.1) {
          const d = new VDev(c.users[Math.floor(Math.random() * c.users.length)]!);
          const r = await d.activate(c.http);
          if (r.ok) active.push(d);
          return r;
        }
        const d = active[Math.floor(Math.random() * active.length)]!;
        return d.deviceCall(c.http, x < 0.8 ? 'refresh' : 'validate');
      };
      let lastCpu = baseline.proc.cpuS,
        lastT = performance.now();
      const rep = await openLoop({
        name: 'soak',
        rps,
        durationS: minutes * 60,
        maxInFlight: 400,
        windowS,
        op: mixed,
        onTick: async (t) => {
          if (Math.floor(t) % 30 !== 0) return;
          const p = procSum(c),
            now = performance.now();
          const s = await dbStats(),
            m = await serverMetrics(c);
          timeline.push({
            tS: Math.round(t),
            srvRssMb: p.rssMb,
            srvCpuPct: round(((p.cpuS - lastCpu) / ((now - lastT) / 1000)) * 100, 0),
            heapMb: round(m.gauges['process_heap_used_bytes'] / 1048576, 1),
            evLoopP99: m.gauges['process_event_loop_delay_p99_ms'],
            pgConns: s.conns,
            poolWaiting: m.gauges['db_pool_waiting'],
            audit: s.tables['audit_events'],
            leases: s.tables['leases'],
            challenges: s.tables['challenges'],
            loadavg: loadavg(),
          });
          lastCpu = p.cpuS;
          lastT = now;
          log(
            `t=${Math.round(t)}s rss ${p.rssMb}MB cpu ${(timeline.at(-1) as any).srvCpuPct}% audit_rows ${s.tables['audit_events']?.rows} challenges_rows ${s.tables['challenges']?.rows}`,
          );
        },
      });
      const m1 = await serverMetrics(c);
      const v0 = performance.now();
      const verify = (
        await c.http.request('GET', '/v1/admin/audit/verify', undefined, c.operatorToken)
      ).body;
      const verifyMs = round(performance.now() - v0, 0);
      // invariants straight from the database
      const inv = (
        await dbc.query(`SELECT
         (SELECT count(*) FROM (SELECT l.id FROM licenses l JOIN plans p ON p.id=l.plan_id JOIN activations a ON a.license_id=l.id AND a.status='active' GROUP BY l.id, p.device_limit HAVING count(*) > p.device_limit) x)::int AS licenses_over_limit,
         (SELECT count(*) FROM challenges WHERE consumed_at IS NOT NULL)::int AS consumed_challenges,
         (SELECT count(*) FROM leases)::int AS leases,
         (SELECT count(*) FROM audit_events)::int AS audit_rows`)
      ).rows[0];
      result['soak'] = {
        rps,
        minutes,
        report: { ...rep, windows: rep.windows },
        timeline,
        server: serverDelta(baseline.m, m1),
        verify,
        verifyMs,
        invariants: inv,
        final: await dbStats(),
      };
      log('verify', JSON.stringify(verify), `${verifyMs}ms`, 'invariants', JSON.stringify(inv));
    });
  },

  async 'pool-sweep'() {
    const rows: unknown[] = [];
    for (const pool of list('pools', [5, 10, 20, 40])) {
      await dbc.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;'); // fresh database state per pool size
      await withServer(num('users', 1000), 10, pool, async (c) => {
        const devs = c.users.map((u) => new VDev(u));
        await activateMany(c, devs, 32);
        const rps = num('rps', 400);
        const r = await step(c, `refresh pool=${pool}`, rps, num('seconds', 20), (i) =>
          i % 5 === 0
            ? new VDev(c.users[i % c.users.length]!).activate(c.http)
            : devs[i % devs.length]!.deviceCall(c.http, 'refresh'),
        );
        rows.push({ pool, ...r });
      });
    }
    result['rows'] = rows;
  },
};

const name = args.get('scenario') ?? '';
if (!scenarios[name]) {
  console.error(`unknown scenario "${name}". Options: ${Object.keys(scenarios).join(', ')}`);
  process.exit(2);
}
await dbc.connect();
try {
  await scenarios[name]!();
} finally {
  await dbc.end();
}
result['finishedAt'] = new Date().toISOString();
if (args.has('assert-clean') && dirty > 0) {
  console.error(`--assert-clean: ${dirty} step(s) saw errors or dropped operations`);
  process.exit(1);
}
if (args.has('out')) {
  writeFileSync(args.get('out')!, JSON.stringify(result, null, 2));
  log('wrote', args.get('out'));
}
process.exit(0);
