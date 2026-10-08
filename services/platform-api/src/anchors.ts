import { createAnchor, type AnchorManifest, type AuditLog } from '@trust/audit';
import { canonicalJson, newId } from '@trust/crypto';
import type { Clock } from '@trust/shared-types';
import type { Metrics } from './metrics.ts';

// ADR-010: publish the audit-log anchor to an external append-only witness, so that a complete, internally
// consistent rewrite of the log by someone with database superuser rights becomes detectable.

export interface AnchorRecord {
  id: string;
  createdAt: Date;
  anchor: string;
  chains: number;
  events: number;
  /** Origin + path of the witness. Never credentials or query strings. */
  destination: string;
  status: 'published' | 'failed';
  receipt: string | null;
  /** Short, secret-free reason when `status` is `failed`. */
  error: string | null;
}

export interface AnchorStore {
  record(r: AnchorRecord): Promise<void>;
  /** Most recent record with the given status (any status if omitted). */
  latest(status?: AnchorRecord['status']): Promise<AnchorRecord | undefined>;
  /** Newest first. */
  list(limit: number): Promise<AnchorRecord[]>;
}

export class InMemoryAnchorStore implements AnchorStore {
  readonly #rows: AnchorRecord[] = [];
  async record(r: AnchorRecord) {
    this.#rows.push({ ...r });
  }
  async latest(status?: AnchorRecord['status']) {
    const r = [...this.#rows].reverse().find((x) => status === undefined || x.status === status);
    return r ? { ...r } : undefined;
  }
  async list(limit: number) {
    return [...this.#rows]
      .reverse()
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }
}

// ---- the witness endpoint ----------------------------------------------------------------------------------

export interface AnchorSink {
  /** Stable label for records and logs (no credentials). */
  readonly destination: string;
  /** Resolves with the witness's receipt reference, or rejects with a short, secret-free Error. */
  publish(manifest: AnchorManifest): Promise<{ receipt: string | null }>;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Returns the validated witness URL. https is required, except loopback http outside production (local witness
 * for development and tests). Credentials in the URL are refused: the token travels in a header.
 */
export function validateAnchorUrl(raw: string, production: boolean): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('invalid AUDIT_ANCHOR_URL');
  }
  if (u.username || u.password) throw new Error('AUDIT_ANCHOR_URL must not contain credentials');
  const loopbackHttp = u.protocol === 'http:' && LOOPBACK.has(u.hostname) && !production;
  if (u.protocol !== 'https:' && !loopbackHttp) throw new Error('AUDIT_ANCHOR_URL must be https');
  return u;
}

export class HttpsAnchorSink implements AnchorSink {
  readonly destination: string;
  readonly #url: string;
  readonly #token: string | undefined;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(
    url: URL,
    opts: { token?: string | undefined; timeoutMs?: number; fetch?: typeof fetch } = {},
  ) {
    this.#url = url.toString();
    this.destination = `${url.origin}${url.pathname}`;
    this.#token = opts.token;
    this.#timeoutMs = opts.timeoutMs ?? 10_000;
    this.#fetch = opts.fetch ?? fetch;
  }

  async publish(manifest: AnchorManifest): Promise<{ receipt: string | null }> {
    let res: Response;
    try {
      res = await this.#fetch(this.#url, {
        method: 'POST',
        redirect: 'error', // never follow a redirect to somewhere the operator did not configure
        signal: AbortSignal.timeout(this.#timeoutMs),
        headers: {
          'content-type': 'application/json',
          'idempotency-key': manifest.anchor, // re-sending the same state is harmless
          ...(this.#token ? { authorization: `Bearer ${this.#token}` } : {}),
        },
        body: canonicalJson(manifest),
      });
    } catch (e) {
      // Do not forward the error text: it can contain the URL. The class of failure is enough to act on.
      throw new Error(
        (e as Error)?.name === 'TimeoutError' ? 'witness timed out' : 'witness unreachable',
      );
    }
    await res.body?.cancel().catch(() => undefined);
    if (!res.ok) throw new Error(`witness responded ${res.status}`);
    const receipt = res.headers.get('x-witness-receipt');
    return { receipt: receipt && /^[\x21-\x7e]{1,256}$/.test(receipt) ? receipt : null };
  }
}

// ---- publishing ----------------------------------------------------------------------------------------------

export type PublishOutcome =
  | { status: 'published'; record: AnchorRecord }
  | { status: 'failed'; record: AnchorRecord }
  | { status: 'unchanged'; anchor: string }
  | { status: 'chain_invalid'; chain: string; brokenAtSeq: number; reason: string };

export interface AnchorDeps {
  audit: AuditLog;
  store: AnchorStore;
  sink: AnchorSink;
  clock: Clock;
  metrics?: Metrics;
  /** Called when the log fails verification (critical): raise the security signal / page someone. */
  onChainInvalid?: (f: { chain: string; brokenAtSeq: number; reason: string }) => Promise<void>;
}

export class AnchorPublisher {
  readonly #d: AnchorDeps;
  #running = false;
  #lastSuccessMs: number | undefined;

  constructor(d: AnchorDeps) {
    this.#d = d;
    d.metrics?.gauge('audit_anchor_last_success_age_seconds', () =>
      this.#lastSuccessMs === undefined ? -1 : (Date.now() - this.#lastSuccessMs) / 1000,
    );
  }

  get destination(): string {
    return this.#d.sink.destination;
  }

  /** Seeds the "last success" gauge from the stored history after a restart. */
  async init(): Promise<void> {
    const last = await this.#d.store.latest('published');
    if (last) this.#lastSuccessMs = last.createdAt.getTime();
  }

  /**
   * Verifies the whole log, then witnesses its heads. A log that fails verification is NOT published (that would
   * bless the tampering) and raises the alert instead. `force` publishes even if nothing changed since the last
   * successful publication.
   */
  async publish(opts: { force?: boolean } = {}): Promise<PublishOutcome> {
    if (this.#running) throw new Error('an anchor publication is already running');
    this.#running = true;
    const m = this.#d.metrics;
    try {
      const at = this.#d.clock.now();
      const made = await createAnchor(this.#d.audit, at);
      if (!made.ok) {
        m?.inc('audit_anchor_publish_total', { outcome: 'chain_invalid' });
        const f = { chain: made.chain, brokenAtSeq: made.brokenAtSeq, reason: made.reason };
        await this.#d.onChainInvalid?.(f);
        return { status: 'chain_invalid', ...f };
      }
      const { manifest } = made;
      if (!opts.force && (await this.#d.store.latest('published'))?.anchor === manifest.anchor) {
        m?.inc('audit_anchor_publish_total', { outcome: 'unchanged' });
        this.#lastSuccessMs = Date.now(); // still anchored: the witness already holds exactly this state
        return { status: 'unchanged', anchor: manifest.anchor };
      }
      const base = {
        id: newId('anc'),
        createdAt: at,
        anchor: manifest.anchor,
        chains: manifest.chains.length,
        events: manifest.chains.reduce((n, c) => n + c.seq, 0),
        destination: this.#d.sink.destination,
      };
      let record: AnchorRecord;
      try {
        const { receipt } = await this.#d.sink.publish(manifest);
        record = { ...base, status: 'published', receipt, error: null };
        this.#lastSuccessMs = Date.now();
      } catch (e) {
        record = {
          ...base,
          status: 'failed',
          receipt: null,
          error: String((e as Error)?.message ?? 'failed').slice(0, 200),
        };
      }
      await this.#d.store.record(record);
      m?.inc('audit_anchor_publish_total', { outcome: record.status });
      return { status: record.status, record };
    } finally {
      this.#running = false;
    }
  }
}

export interface AnchoringHandle {
  stop(): void;
  runOnce(): Promise<PublishOutcome | undefined>;
}

/** Periodic publication. Errors are reported, never thrown; the next tick retries. */
export function startAnchoring(
  p: AnchorPublisher,
  opts: {
    everyMs: number;
    firstRunMs?: number;
    onError?: (e: unknown) => void;
    /** Every completed attempt, including refusals and failures (which are results, not exceptions). */
    onOutcome?: (o: PublishOutcome) => void;
  },
): AnchoringHandle {
  const runOnce = async () => {
    try {
      const o = await p.publish();
      opts.onOutcome?.(o);
      return o;
    } catch (e) {
      opts.onError?.(e);
      return undefined;
    }
  };
  const interval = setInterval(() => void runOnce(), opts.everyMs);
  interval.unref();
  // Publish soon after start so a new deployment is witnessed quickly, not only after a full interval.
  const first = setTimeout(() => void runOnce(), opts.firstRunMs ?? 5_000);
  first.unref();
  return {
    stop: () => {
      clearInterval(interval);
      clearTimeout(first);
    },
    runOnce,
  };
}
