import { expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createSchemaPool } from '../../../tests/support/pg.ts';
import { PgMobileStore } from '../src/db/pg-mobile-store.ts';
import { MobileAnalytics, mobileBatch } from '../src/mobile-analytics.ts';
it('enforces the retained-event cap atomically and frees capacity with bounded retention', async () => {
  const pool = createSchemaPool();
  const now = new Date('2026-03-01T00:00:00Z');
  const service = new MobileAnalytics(new PgMobileStore(pool), { now: () => now });
  const batch = mobileBatch.parse({
    installation_id: randomUUID(),
    events: [
      {
        id: randomUUID(),
        occurred_at: now.toISOString(),
        feature: 'app_open',
        app_version: '1',
        os_major: null,
        device_class: 'unknown',
      },
    ],
  });
  await pool.query(
    "INSERT INTO mobile_analytics_events(id,installation,digest,occurred_at,received_at,feature,app_version,device_class) SELECT md5(g::text)::uuid,repeat('a',64),repeat('b',64),$1,$1,'app_open','1','unknown' FROM generate_series(1,100000) AS g",
    [new Date(+now - 31 * 86400000)],
  );
  await expect(service.accept(batch, null)).rejects.toMatchObject({ code: 'rate_limited' });
  expect(
    Number((await pool.query('SELECT count(*) AS n FROM mobile_analytics_events')).rows[0]!.n),
  ).toBe(100000);
  expect(await service.retain()).toBe(1000);
  await service.accept(batch, null);
  expect((await service.summary()).reports).toBe(1);
  expect(
    Number((await pool.query('SELECT count(*) AS n FROM mobile_analytics_events')).rows[0]!.n),
  ).toBe(99001);
}, 30000);
