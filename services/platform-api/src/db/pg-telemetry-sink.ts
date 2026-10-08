import type { SecurityRecord, TelemetryRecord, TelemetrySink } from '@trust/telemetry';
import type { PgPool } from './pg.ts';

/** Attributes are already allow-listed/redacted by the `Telemetry` facade before reaching storage. */
export class PgTelemetrySink implements TelemetrySink {
  readonly #pool: PgPool;
  constructor(pool: PgPool) {
    this.#pool = pool;
  }
  async recordTelemetry(r: TelemetryRecord): Promise<void> {
    await this.#pool.query(
      'INSERT INTO telemetry_events (id, occurred_at, name, attributes) VALUES ($1,$2,$3,$4)',
      [r.id, r.occurredAt, r.name, r.attributes],
    );
  }
  async recordSecurity(r: SecurityRecord): Promise<void> {
    await this.#pool.query(
      'INSERT INTO security_events (id, occurred_at, kind, severity, org_id, subject, attributes) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [r.id, r.occurredAt, r.kind, r.severity, r.orgId, r.subject, r.attributes],
    );
  }
}
