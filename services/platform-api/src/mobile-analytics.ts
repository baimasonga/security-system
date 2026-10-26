import { createHash } from 'node:crypto';
import { z } from 'zod';
import { DomainError, type Clock } from '@trust/shared-types';

export const MOBILE_FEATURES = [
  'open',
  'scan',
  'sign',
  'edit',
  'pages',
  'merge',
  'photos',
  'compress',
  'protect',
  'unlock',
  'ocr',
  'fill',
  'convert',
] as const;
export const mobileBatch = z
  .object({
    installation_id: z.uuid(),
    events: z
      .array(
        z
          .object({
            id: z.uuid(),
            occurred_at: z.iso.datetime(),
            feature: z.enum(['app_open', ...MOBILE_FEATURES]),
            app_version: z.string().regex(/^[0-9]{1,4}(\.[0-9]{1,4}){0,3}$/),
            os_major: z.number().int().min(1).max(99).nullable(),
            device_class: z.enum(['phone', 'tablet', 'unknown']),
          })
          .strict(),
      )
      .min(1)
      .max(20),
  })
  .strict();
export type MobileBatch = z.infer<typeof mobileBatch>;
export interface MobileRecord {
  id: string;
  installation: string;
  occurredAt: Date;
  receivedAt: Date;
  feature: MobileBatch['events'][number]['feature'];
  appVersion: string;
  osMajor: number | null;
  deviceClass: string;
  country: string | null;
  digest: string;
}
export interface MobileStore {
  /** Atomic: exact retries are accepted; conflicting IDs and quota overflow reject the batch. */
  accept(records: MobileRecord[]): Promise<void>;
  recent(since: Date): Promise<MobileRecord[]>;
  retain(before: Date): Promise<number>;
}
export const MOBILE_MAX_RECORDS = 100000;
export class MemoryMobileStore implements MobileStore {
  readonly rows = new Map<string, MobileRecord>();
  async accept(records: MobileRecord[]) {
    const next = new Map(this.rows);
    for (const row of records) {
      const existing = next.get(row.id);
      if (existing && existing.digest !== row.digest)
        throw new DomainError('conflict', 'conflicting analytics event');
      if (!existing) next.set(row.id, row);
    }
    if (next.size > MOBILE_MAX_RECORDS)
      throw new DomainError('rate_limited', 'analytics capacity reached');
    for (const [id, row] of next) this.rows.set(id, row);
  }
  async recent(since: Date) {
    return [...this.rows.values()].filter((row) => row.receivedAt >= since);
  }
  async retain(before: Date) {
    let n = 0;
    for (const [id, row] of this.rows)
      if (n < 1000 && row.receivedAt < before) {
        this.rows.delete(id);
        n++;
      }
    return n;
  }
}
const DAY = 86400000;
export class MobileAnalytics {
  readonly store: MobileStore;
  readonly clock: Clock;
  constructor(store: MobileStore, clock: Clock) {
    this.store = store;
    this.clock = clock;
  }
  async accept(batch: MobileBatch, country: string | null) {
    const now = this.clock.now();
    const installation = createHash('sha256')
      .update('rokela-android:' + batch.installation_id.toLowerCase())
      .digest('hex');
    const records = batch.events.map((event) => {
      const at = new Date(event.occurred_at);
      if (+at < +now - 7 * DAY || +at > +now + 300000)
        throw new DomainError('invalid_request', 'analytics event outside accepted window');
      const normalized = [
        installation,
        event.id.toLowerCase(),
        at.toISOString(),
        event.feature,
        event.app_version,
        event.os_major,
        event.device_class,
      ];
      return {
        id: event.id.toLowerCase(),
        installation,
        occurredAt: at,
        receivedAt: now,
        feature: event.feature,
        appVersion: event.app_version,
        osMajor: event.os_major,
        deviceClass: event.device_class,
        country: country && /^[A-Z]{2}$/.test(country) ? country : null,
        digest: createHash('sha256').update(JSON.stringify(normalized)).digest('hex'),
      };
    });
    await this.store.accept(records);
    return { accepted: batch.events.length };
  }
  retain() {
    return this.store.retain(new Date(+this.clock.now() - 30 * DAY));
  }
  async summary() {
    const now = this.clock.now();
    const rows = await this.store.recent(new Date(+now - 30 * DAY));
    const ids = (items: MobileRecord[]) => new Set(items.map((r) => r.installation)).size;
    const buckets = (key: (r: MobileRecord) => string) => {
      const grouped = new Map<string, MobileRecord[]>();
      for (const row of rows) {
        const k = key(row);
        const group = grouped.get(k) ?? [];
        group.push(row);
        grouped.set(k, group);
      }
      return [...grouped]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([label, items]) => ({ label, events: items.length, installations: ids(items) }));
    };
    const countries = buckets((r) => r.country ?? 'unknown');
    // Do not release rare country labels/counts; no geography filters or per-installation reads.
    const visible = countries.filter((r) => r.label !== 'unknown' && r.installations >= 5);
    return {
      source: 'anonymous_client_reports',
      app: 'rokela-pdf-android',
      generated_at: now.toISOString(),
      window_days: 30,
      last_received_at: rows.length
        ? new Date(rows.reduce((latest, r) => Math.max(latest, +r.receivedAt), 0)).toISOString()
        : null,
      reports: rows.length,
      active_installations_30d: ids(rows),
      active_installations_7d: ids(rows.filter((r) => +r.receivedAt >= +now - 7 * DAY)),
      active_installations_1d: ids(rows.filter((r) => +r.receivedAt >= +now - DAY)),
      features: buckets((r) => r.feature),
      versions: buckets((r) => r.appVersion),
      devices: buckets((r) => r.deviceClass),
      android_versions: buckets((r) => (r.osMajor === null ? 'unknown' : String(r.osMajor))),
      daily_reports: buckets((r) => r.receivedAt.toISOString().slice(0, 10)),
      countries: visible,
      country_coverage:
        'Countries with fewer than five reporting installations and unknown locations are not shown.',
    };
  }
}
