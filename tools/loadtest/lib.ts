import http from 'node:http';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

// ---- HTTP client (keep-alive, bounded sockets) ------------------------------------------------
export class Http {
  readonly #agent: http.Agent;
  readonly #host: string;
  readonly #port: number;
  constructor(base: string, maxSockets: number) {
    const u = new URL(base);
    this.#host = u.hostname;
    this.#port = Number(u.port);
    this.#agent = new http.Agent({ keepAlive: true, maxSockets, maxFreeSockets: maxSockets });
  }
  request(
    method: string,
    path: string,
    body?: unknown,
    token?: string,
  ): Promise<{ status: number; body: any }> {
    return new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request(
        {
          agent: this.#agent,
          host: this.#host,
          port: this.#port,
          method,
          path,
          headers: {
            ...(payload
              ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
              : {}),
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: any = undefined;
            try {
              parsed = text ? JSON.parse(text) : undefined;
            } catch {
              parsed = text;
            }
            resolve({ status: res.statusCode ?? 0, body: parsed });
          });
        },
      );
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
  destroy() {
    this.#agent.destroy();
  }
}

// ---- statistics -----------------------------------------------------------------------------
export function percentiles(
  samples: number[],
  ps = [50, 90, 95, 99, 99.9],
): Record<string, number> {
  if (samples.length === 0) return Object.fromEntries(ps.map((p) => [`p${p}`, 0]));
  const a = Float64Array.from(samples).sort();
  const out: Record<string, number> = {};
  for (const p of ps)
    out[`p${p}`] = round(a[Math.min(a.length - 1, Math.ceil((p / 100) * a.length) - 1)]!);
  return out;
}
export const round = (n: number, d = 2) => Math.round(n * 10 ** d) / 10 ** d;
export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface OpResult {
  ok: boolean;
  code: string;
}
export interface StepReport {
  name: string;
  targetRps: number;
  durationS: number;
  launched: number;
  completed: number;
  dropped: number;
  achievedRps: number;
  ok: number;
  errors: Record<string, number>;
  latencyMs: Record<string, number>;
  maxMs: number;
  // windowed p99 for drift detection
  windows?: Array<{ tS: number; n: number; p99: number; errors: number }>;
}

/**
 * OPEN-LOOP load: operations are launched on a fixed schedule regardless of how slow the server is,
 * and latency is measured from the INTENDED start time. A closed loop would let a slow server throttle
 * the generator and hide the queueing (coordinated omission).
 */
export async function openLoop(opts: {
  name: string;
  rps: number;
  durationS: number;
  maxInFlight: number;
  windowS?: number;
  op: (i: number) => Promise<OpResult>;
  onTick?: (elapsedS: number) => void | Promise<void>;
}): Promise<StepReport> {
  const lat: number[] = [];
  const errors: Record<string, number> = {};
  const wins = new Map<number, { lat: number[]; errors: number }>();
  let launched = 0,
    completed = 0,
    dropped = 0,
    ok = 0,
    inFlight = 0,
    maxLat = 0;
  const start = performance.now();
  const total = Math.floor(opts.rps * opts.durationS);
  const winMs = (opts.windowS ?? 30) * 1000;
  const pending: Promise<void>[] = [];
  let lastTick = 0;

  while (launched + dropped < total) {
    const now = performance.now();
    const due = Math.min(total, Math.floor(((now - start) / 1000) * opts.rps));
    while (launched + dropped < due) {
      const i = launched + dropped;
      const intended = start + (i / opts.rps) * 1000;
      if (inFlight >= opts.maxInFlight) {
        dropped++;
        continue;
      } // generator-side saturation: reported, not hidden
      launched++;
      inFlight++;
      pending.push(
        opts.op(i).then(
          (r) => finish(intended, r),
          (e) =>
            finish(intended, {
              ok: false,
              code: `client:${(e as NodeJS.ErrnoException).code ?? 'error'}`,
            }),
        ),
      );
    }
    if (opts.onTick && now - lastTick >= 1000) {
      lastTick = now;
      await opts.onTick((now - start) / 1000);
    }
    await sleep(1);
  }
  await Promise.all(pending);
  const elapsedS = (performance.now() - start) / 1000;

  function finish(intended: number, r: OpResult) {
    const l = performance.now() - intended;
    inFlight--;
    completed++;
    lat.push(l);
    if (l > maxLat) maxLat = l;
    if (r.ok) ok++;
    else errors[r.code] = (errors[r.code] ?? 0) + 1;
    const w = Math.floor((intended - start) / winMs);
    let b = wins.get(w);
    if (!b) wins.set(w, (b = { lat: [], errors: 0 }));
    b.lat.push(l);
    if (!r.ok) b.errors++;
  }

  return {
    name: opts.name,
    targetRps: opts.rps,
    durationS: round(elapsedS, 1),
    launched,
    completed,
    dropped,
    achievedRps: round(completed / elapsedS, 1),
    ok,
    errors,
    latencyMs: percentiles(lat),
    maxMs: round(maxLat),
    windows: [...wins.entries()]
      .sort(([a], [b]) => a - b)
      .map(([w, b]) => ({
        tS: (w * winMs) / 1000,
        n: b.lat.length,
        p99: percentiles(b.lat, [99])['p99']!,
        errors: b.errors,
      })),
  };
}

// ---- process sampling -------------------------------------------------------------------------
const TICKS = 100; // CLK_TCK on Linux
export function procStat(
  pid: number,
): { cpuS: number; rssMb: number; threads: number } | undefined {
  try {
    const st = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const f = st.slice(st.lastIndexOf(')') + 2).split(' ');
    const cpuS = (Number(f[11]) + Number(f[12])) / TICKS; // utime + stime
    const status = readFileSync(`/proc/${pid}/status`, 'utf8');
    const rssKb = Number(/VmRSS:\s+(\d+)/.exec(status)?.[1] ?? 0);
    const threads = Number(/Threads:\s+(\d+)/.exec(status)?.[1] ?? 0);
    return { cpuS, rssMb: round(rssKb / 1024, 1), threads };
  } catch {
    return undefined;
  }
}
export function loadavg(): number {
  return round(Number(readFileSync('/proc/loadavg', 'utf8').split(' ')[0]), 2);
}
