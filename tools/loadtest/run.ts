// Load / soak test driver. Run under an ephemeral PostgreSQL:
//   PG_FSYNC=on node tools/with-postgres.mjs node tools/loadtest/run.ts --scenario <name> [--out file.json] [opts]
// Scenarios: audit-micro | activate-ramp | refresh-ramp | hot-license | herd | soak | pool-sweep
import { writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import pg from 'pg';
import { PgAuditLog } from '../../services/platform-api/src/db/pg-audit-log.ts';
import {
  Http,
  loadavg,
  openLoop,
  percentiles,
  procStat,
  round,
  sleep,
  type OpResult,
  type StepReport,
} from './lib.ts';
import { VDev, seedWorld, startServer, type Server, type SeedUser } from './world.ts';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2)
  args.set(process.argv[i]!.replace(/^--/, ''), process.argv[i + 1] ?? '');
const num = (k: string, d: number) => (args.has(k) ? Number(args.get(k)) : d);
const list = (k: string, d: number[]) => (args.has(k) ? args.get(k)!.split(',').map(Number) : d);
const dbUrl = process.env['DATABASE_URL']!;
if (!dbUrl) throw new Error('DATABASE_URL required (run via tools/with-postgres.mjs)');

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
    "SELECT relname, (pg_total_relation_size(c.oid)/1048576.0)::numeric(10,2)::float AS mb, reltuples::bigint::int AS rows FROM pg_class c WHERE relname IN ('audit_events','leases','challenges','activations','devices') AND relkind='r'",
  );
  return {
    ...a,
    ...d,
    tables: Object.fromEntries(sizes.map((s: any) => [s.relname, { mb: s.mb, rows: s.rows }])),
  };
}
async function serverMetrics(h: Http, token: string): Promise<any> {
  return (await h.request('GET', '/v1/admin/metrics', undefined, token)).body;
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
    eventLoopP99Ms: after.gauges['process_event_loop_delay_p99_ms'],
    poolWaiting: after.gauges['db_pool_waiting'],
    poolTotal: after.gauges['db_pool_total'],
  };
}

interface Ctx {
  srv: Server;
  http: Http;
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
  const srv = await startServer(dbUrl, { port: PORT, pool, logLevel: args.get('log') ?? 'info' });
  const http = new Http(srv.base, 256);
  try {
    return await fn({
      srv,
      http,
      users: w.users,
      operatorToken: w.operatorToken,
      extras: w.extras,
    });
  } finally {
    http.destroy();
    await srv.stop();
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
  const m0 = await serverMetrics(c.http, c.operatorToken);
  const p0 = procStat(c.srv.pid)!;
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
      const m = await serverMetrics(c.http, c.operatorToken);
      poolWaitMax = Math.max(poolWaitMax, m.gauges['db_pool_waiting'] ?? 0);
    },
  });
  const m1 = await serverMetrics(c.http, c.operatorToken);
  const p1 = procStat(c.srv.pid)!;
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
    loadavg: loadavg(),
  };
  const errs =
    Object.entries(rep.errors)
      .map(([k, v]) => `${k}=${v}`)
      .join(' ') || '-';
  log(
    `${name.padEnd(22)} target ${String(rps).padStart(4)} rps → ${String(rep.achievedRps).padStart(6)} rps  p50 ${rep.latencyMs['p50']} p95 ${rep.latencyMs['p95']} p99 ${rep.latencyMs['p99']} max ${rep.maxMs}ms  dropped ${rep.dropped}  err: ${errs}  srvCPU ${out.server.cpuPct}%  retries ${out.server.txRetries} lockwait ${out.server.auditLockWaitMeanMs}ms  deadlocks ${out.db.deadlocks}`,
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
  async 'audit-micro'() {
    await seedWorld(dbUrl, { users: 1, deviceLimit: 1 });
    const rows: unknown[] = [];
    for (const conc of list('conc', [1, 2, 4, 8, 16, 32, 64])) {
      const pool = new pg.Pool({ connectionString: dbUrl, max: conc });
      const log_ = new PgAuditLog(pool, { now: () => new Date() });
      const lat: number[] = [];
      let stop = false,
        n = 0;
      setTimeout(() => (stop = true), num('seconds', 6) * 1000);
      const t0 = performance.now();
      await Promise.all(
        Array.from({ length: conc }, async () => {
          while (!stop) {
            const s = performance.now();
            await log_.append({
              actor: { type: 'system' },
              action: 'bench.event',
              metadata: { n: 1 },
            });
            lat.push(performance.now() - s);
            n++;
          }
        }),
      );
      const secs = (performance.now() - t0) / 1000;
      const row = {
        concurrency: conc,
        eventsPerSec: round(n / secs, 0),
        latencyMs: percentiles(lat, [50, 99]),
      };
      rows.push(row);
      log(JSON.stringify(row));
      await pool.end();
    }
    const v0 = performance.now();
    const verify = await new PgAuditLog(new pg.Pool({ connectionString: dbUrl }), {
      now: () => new Date(),
    }).verifyChain();
    result['verifyChain'] = { ...verify, ms: round(performance.now() - v0, 0) };
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
        const m0 = await serverMetrics(c.http, c.operatorToken);
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
        const m1 = await serverMetrics(c.http, c.operatorToken);
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
        proc: procStat(c.srv.pid)!,
        m: await serverMetrics(c.http, c.operatorToken),
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
          const p = procStat(c.srv.pid)!,
            now = performance.now();
          const s = await dbStats(),
            m = await serverMetrics(c.http, c.operatorToken);
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
      const m1 = await serverMetrics(c.http, c.operatorToken);
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
if (args.has('out')) {
  writeFileSync(args.get('out')!, JSON.stringify(result, null, 2));
  log('wrote', args.get('out'));
}
process.exit(0);
