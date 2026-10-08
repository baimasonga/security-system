import { monitorEventLoopDelay } from 'node:perf_hooks';

// Minimal, dependency-free operational metrics. Labels are low-cardinality by construction: callers
// pass route TEMPLATES and enumerated outcomes, never ids, emails, tokens or free text.

const BUCKETS_MS = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

type Labels = Record<string, string>;
const keyOf = (name: string, labels?: Labels) =>
  labels && Object.keys(labels).length
    ? `${name}{${Object.entries(labels)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}="${v.replace(/[\\"\n]/g, '_')}"`)
        .join(',')}}`
    : name;

interface Hist {
  count: number;
  sum: number;
  max: number;
  buckets: number[]; // cumulative-ready counts per BUCKETS_MS (+Inf at the end)
}

export interface MetricsSnapshot {
  counters: Record<string, number>;
  gauges: Record<string, number>;
  histograms: Record<
    string,
    {
      count: number;
      sum_ms: number;
      max_ms: number;
      mean_ms: number;
      p50_ms: number;
      p95_ms: number;
      p99_ms: number;
    }
  >;
}

export class Metrics {
  readonly #counters = new Map<string, number>();
  readonly #hists = new Map<string, Hist>();
  readonly #gauges = new Map<string, () => number>();
  readonly #loop = monitorEventLoopDelay({ resolution: 10 });

  constructor() {
    this.#loop.enable();
    this.gauge('process_rss_bytes', () => process.memoryUsage.rss());
    this.gauge('process_heap_used_bytes', () => process.memoryUsage().heapUsed);
    this.gauge('process_event_loop_delay_p99_ms', () => this.#loop.percentile(99) / 1e6);
    this.gauge('process_event_loop_delay_max_ms', () => this.#loop.max / 1e6);
  }

  inc(name: string, labels?: Labels, by = 1): void {
    const k = keyOf(name, labels);
    this.#counters.set(k, (this.#counters.get(k) ?? 0) + by);
  }

  observe(name: string, ms: number, labels?: Labels): void {
    const k = keyOf(name, labels);
    let h = this.#hists.get(k);
    if (!h)
      this.#hists.set(
        k,
        (h = { count: 0, sum: 0, max: 0, buckets: new Array(BUCKETS_MS.length + 1).fill(0) }),
      );
    h.count++;
    h.sum += ms;
    if (ms > h.max) h.max = ms;
    let i = BUCKETS_MS.findIndex((b) => ms <= b);
    if (i < 0) i = BUCKETS_MS.length;
    h.buckets[i]!++;
  }

  gauge(name: string, read: () => number): void {
    this.#gauges.set(name, read);
  }

  /** Upper-bound percentile estimate from the fixed buckets (never under-reports). */
  static quantile(h: Hist, q: number): number {
    if (h.count === 0) return 0;
    const target = Math.ceil(q * h.count);
    let seen = 0;
    for (let i = 0; i < h.buckets.length; i++) {
      seen += h.buckets[i]!;
      if (seen >= target) return i < BUCKETS_MS.length ? BUCKETS_MS[i]! : h.max;
    }
    return h.max;
  }

  snapshot(): MetricsSnapshot {
    const histograms: MetricsSnapshot['histograms'] = {};
    for (const [k, h] of this.#hists) {
      histograms[k] = {
        count: h.count,
        sum_ms: round(h.sum),
        max_ms: round(h.max),
        mean_ms: round(h.sum / h.count),
        p50_ms: Metrics.quantile(h, 0.5),
        p95_ms: Metrics.quantile(h, 0.95),
        p99_ms: Metrics.quantile(h, 0.99),
      };
    }
    const gauges: Record<string, number> = {};
    for (const [k, read] of this.#gauges) gauges[k] = round(read());
    return { counters: Object.fromEntries(this.#counters), gauges, histograms };
  }

  /** Prometheus text exposition format. */
  prometheus(): string {
    const lines: string[] = [];
    for (const [k, v] of this.#counters) lines.push(`trust_${k} ${v}`);
    for (const [k, read] of this.#gauges) lines.push(`trust_${k} ${round(read())}`);
    for (const [k, h] of this.#hists) {
      const [name, lab] = k.includes('{')
        ? [k.slice(0, k.indexOf('{')), k.slice(k.indexOf('{') + 1, -1)]
        : [k, ''];
      const sep = lab ? `${lab},` : '';
      let cum = 0;
      h.buckets.forEach((n, i) => {
        cum += n;
        lines.push(
          `trust_${name}_bucket{${sep}le="${i < BUCKETS_MS.length ? BUCKETS_MS[i] : '+Inf'}"} ${cum}`,
        );
      });
      lines.push(`trust_${name}_sum${lab ? `{${lab}}` : ''} ${round(h.sum)}`);
      lines.push(`trust_${name}_count${lab ? `{${lab}}` : ''} ${h.count}`);
    }
    return lines.join('\n') + '\n';
  }

  close(): void {
    this.#loop.disable();
  }
}

const round = (n: number) => Math.round(n * 1000) / 1000;
