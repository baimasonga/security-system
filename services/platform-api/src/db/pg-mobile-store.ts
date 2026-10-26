import { DomainError } from '@trust/shared-types';
import { MOBILE_MAX_RECORDS, type MobileRecord, type MobileStore } from '../mobile-analytics.ts';
import type { PgPool } from './pg.ts';
export class PgMobileStore implements MobileStore {
  readonly pool: PgPool;
  constructor(pool: PgPool) {
    this.pool = pool;
  }
  async accept(records: MobileRecord[]) {
    const q = await this.pool.connect();
    try {
      await q.query('BEGIN');
      await q.query("SET LOCAL statement_timeout = '5s'");
      await q.query('SELECT pg_advisory_xact_lock(914740)');
      let size = Number(
        (await q.query('SELECT count(*) AS n FROM mobile_analytics_events')).rows[0].n,
      );
      for (const row of records) {
        const existing = (
          await q.query('SELECT digest FROM mobile_analytics_events WHERE id=$1', [row.id])
        ).rows[0];
        if (existing) {
          if (existing.digest !== row.digest)
            throw new DomainError('conflict', 'conflicting analytics event');
          continue;
        }
        if (++size > MOBILE_MAX_RECORDS)
          throw new DomainError('rate_limited', 'analytics capacity reached');
        await q.query(
          'INSERT INTO mobile_analytics_events(id,installation,digest,occurred_at,received_at,feature,app_version,os_major,device_class,country) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
          [
            row.id,
            row.installation,
            row.digest,
            row.occurredAt,
            row.receivedAt,
            row.feature,
            row.appVersion,
            row.osMajor,
            row.deviceClass,
            row.country,
          ],
        );
      }
      await q.query('COMMIT');
    } catch (error) {
      await q.query('ROLLBACK');
      throw error;
    } finally {
      q.release();
    }
  }
  async recent(since: Date): Promise<MobileRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM mobile_analytics_events WHERE received_at >= $1 ORDER BY received_at DESC LIMIT 100000',
      [since],
    );
    return result.rows.map((r) => ({
      id: r.id,
      installation: r.installation,
      digest: r.digest,
      occurredAt: r.occurred_at,
      receivedAt: r.received_at,
      feature: r.feature,
      appVersion: r.app_version,
      osMajor: r.os_major,
      deviceClass: r.device_class,
      country: r.country,
    }));
  }
  async retain(before: Date) {
    return (
      (
        await this.pool.query(
          'DELETE FROM mobile_analytics_events WHERE id IN (SELECT id FROM mobile_analytics_events WHERE received_at < $1 ORDER BY received_at LIMIT 1000)',
          [before],
        )
      ).rowCount ?? 0
    );
  }
}
