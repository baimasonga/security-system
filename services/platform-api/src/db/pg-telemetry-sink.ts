import type { SecurityRecord, TelemetryRecord, TelemetrySink } from '@trust/telemetry';
import type { PgPool } from './pg.ts';

/** Product telemetry is best-effort: bounded memory, dropped (and counted) rather than blocking requests. */
const MAX_BUFFERED = 10_000;

/**
 * Attributes are already allow-listed/redacted by the `Telemetry` facade before reaching storage.
 *
 * Product telemetry (counters about usage) is BUFFERED and written in batches off the request path: it is not
 * authority and not evidence, and a database round trip per device call was ~8 % of the round trips of a
 * flow. Security signals are NOT buffered — they are written before the call returns.
 * A crash can lose up to `flushMs` of product telemetry; `flush()`/`close()` drain it on shutdown.
 */
export class PgTelemetrySink implements TelemetrySink {
  readonly #pool: PgPool;
  readonly #flushMs: number;
  readonly #maxBatch: number;
  #buf: TelemetryRecord[] = [];
  #timer: NodeJS.Timeout | undefined;
  #inflight: Promise<void> = Promise.resolve();
  /** Telemetry records discarded because the buffer was full or a batch could not be written. */
  dropped = 0;

  constructor(pool: PgPool, opts?: { flushMs?: number; maxBatch?: number }) {
    this.#pool = pool;
    this.#flushMs = opts?.flushMs ?? 500;
    this.#maxBatch = opts?.maxBatch ?? 200;
  }

  recordTelemetry(r: TelemetryRecord): void | Promise<void> {
    if (this.#flushMs === 0) return this.#write([r]); // write-through (tests / debugging)
    if (this.#buf.length >= MAX_BUFFERED) {
      this.dropped++;
      return;
    }
    this.#buf.push(r);
    if (this.#buf.length >= this.#maxBatch) void this.flush();
    else if (!this.#timer) {
      this.#timer = setTimeout(() => void this.flush(), this.#flushMs);
      this.#timer.unref();
    }
  }

  /** Writes everything buffered so far; resolves when it (and any earlier flush) has finished. */
  flush(): Promise<void> {
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    const batch = this.#buf;
    this.#buf = [];
    if (batch.length > 0) {
      this.#inflight = this.#inflight.then(() =>
        this.#write(batch).catch(() => {
          this.dropped += batch.length; // best effort: never fail a request or crash on telemetry
        }),
      );
    }
    return this.#inflight;
  }

  async #write(batch: TelemetryRecord[]): Promise<void> {
    await this.#pool.query(
      `INSERT INTO telemetry_events (id, occurred_at, name, attributes)
       SELECT id, occurred_at::timestamptz, name, attributes::jsonb
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS t(id, occurred_at, name, attributes)`,
      [
        batch.map((r) => r.id),
        batch.map((r) => r.occurredAt),
        batch.map((r) => r.name),
        batch.map((r) => JSON.stringify(r.attributes)),
      ],
    );
  }

  async recordSecurity(r: SecurityRecord): Promise<void> {
    await this.#pool.query(
      'INSERT INTO security_events (id, occurred_at, kind, severity, org_id, subject, attributes) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [r.id, r.occurredAt, r.kind, r.severity, r.orgId, r.subject, r.attributes],
    );
  }
}
