import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';
import { startMaintenance } from '../src/maintenance.ts';
import { startSharingWorker } from '../src/sharing-worker.ts';
import { DAY, makeEnv, type Env } from './harness.ts';
import { pdf, sp, tokenOf, upload } from './sharing-support.ts';

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;
const STRONG = 'x'.repeat(40);
const PROD = {
  NODE_ENV: 'production',
  LICENSE_KEY_PEPPER: STRONG,
  PSEUDONYM_KEY: 'p'.repeat(40),
  LICENSE_SIGNING_KEY_PEM: 'pem',
  DATABASE_URL: 'postgres://u:p@db/trust?sslmode=require',
  AUDIT_ANCHOR_DISABLED: 'true',
};
const S3 = {
  SHARING_STORAGE: 's3',
  SHARING_SECRET: 's'.repeat(40),
  SHARING_PUBLIC_ORIGIN: 'https://app.rokela.example',
  SHARING_S3_ENDPOINT: 'https://acct.r2.cloudflarestorage.com',
  SHARING_S3_BUCKET: 'rokela-shares',
  SHARING_S3_ACCESS_KEY_ID: 'AKID',
  SHARING_S3_SECRET_ACCESS_KEY: 'secret',
  CLAMD_HOST: 'clamd.internal',
};

describe('sharing configuration fails closed', () => {
  it('is off in production until configured, and refuses weak or local settings there', () => {
    expect(loadConfig(env(PROD)).sharing).toBeUndefined();
    expect(() =>
      loadConfig(env({ ...PROD, SHARING_STORAGE: 'local', SHARING_SECRET: 's'.repeat(40) })),
    ).toThrow(/SHARING_STORAGE=s3/);
    expect(() => loadConfig(env({ ...PROD, ...S3, SHARING_SECRET: 'short' }))).toThrow(
      /SHARING_SECRET/,
    );
    expect(() => loadConfig(env({ ...PROD, ...S3, SHARING_SECRET: STRONG }))).toThrow(/separate/);
    expect(() =>
      loadConfig(env({ ...PROD, ...S3, SHARING_PUBLIC_ORIGIN: 'http://app.rokela.example' })),
    ).toThrow(/HTTPS/);
    expect(() =>
      loadConfig(env({ ...PROD, ...S3, SHARING_S3_ENDPOINT: 'https://app.rokela.example' })),
    ).toThrow(/separate origin/);
    const { SHARING_S3_BUCKET: _b, ...noBucket } = S3;
    expect(() => loadConfig(env({ ...PROD, ...noBucket }))).toThrow(
      /required with SHARING_STORAGE=s3/,
    );
    const { CLAMD_HOST: _c, ...noAv } = S3;
    expect(() => loadConfig(env({ ...PROD, ...noAv }))).toThrow(/CLAMD_HOST/);
    expect(
      loadConfig(env({ ...PROD, ...noAv, SHARING_MALWARE_SCAN_DISABLED: 'true' })).sharing?.clamd,
    ).toBeUndefined();
    expect(loadConfig(env({ ...PROD, ...S3 })).sharing).toMatchObject({
      storage: { kind: 's3', bucket: 'rokela-shares' },
      clamd: { host: 'clamd.internal', port: 3310 },
    });
  });

  it('validates development settings too', () => {
    expect(loadConfig(env({ NODE_ENV: 'test' })).sharing?.storage.kind).toBe('local');
    expect(() => loadConfig(env({ SHARING_STORAGE: 'ftp' }))).toThrow(/SHARING_STORAGE/);
    expect(() => loadConfig(env({ SHARING_CONTENT_ORIGIN: 'http://127.0.0.1:8080' }))).toThrow(
      /content origin must differ/,
    );
    expect(() => loadConfig(env({ SHARING_EVENT_RETENTION_DAYS: '0' }))).toThrow(
      /SHARING_EVENT_RETENTION_DAYS/,
    );
    expect(() => loadConfig(env({ SHARING_BLOCKED_HOSTS: 'ok.example,not a host' }))).toThrow(
      /SHARING_BLOCKED_HOSTS/,
    );
    expect(loadConfig(env({ SHARING_STORAGE: 'off' })).sharing).toBeUndefined();
  });
});

describe('sharing operator knobs change behaviour end to end', () => {
  let e: Env;
  afterEach(async () => e?.app.close());

  it('SHARING_EVENT_RETENTION_DAYS bounds how long receipts are kept', async () => {
    const run = async (days: string) => {
      const config = loadConfig(env({ NODE_ENV: 'test', SHARING_EVENT_RETENTION_DAYS: days }));
      e = await makeEnv({
        config: {
          sharing: {
            ...config.sharing!,
            storage: {
              ...config.sharing!.storage,
              root: (await import('node:fs')).mkdtempSync(
                `${(await import('node:os')).tmpdir()}/rk-`,
              ),
            } as never,
          },
        },
      });
      const owner = await e.register('knob@example.test');
      const tr = await e.call('POST', `${sp(owner.orgId)}/transfers`, {
        token: owner.token,
        body: { title: 'K', kind: 'temporary' },
      });
      const link = await e.call('POST', `${sp(owner.orgId)}/links`, {
        token: owner.token,
        body: { target_type: 'transfer', target_id: tr.body.id, permission: 'download' },
      });
      await e.call('POST', `/v1/public/shares/${tokenOf(link.body.url)}/open`, { body: {} });
      e.clock.advance(3 * DAY);
      const m = startMaintenance(e.c, { everyMs: 3_600_000 });
      await m.runOnce();
      m.stop();
      const left = (
        await e.call('GET', `${sp(owner.orgId)}/links/${link.body.id}/activity`, {
          token: await e.login('knob@example.test'),
        })
      ).body.events.length;
      const counted =
        e.c.metrics.snapshot().counters['maintenance_deleted_total{table="sharing_events"}'];
      await e.app.close();
      return { left, counted };
    };
    expect(await run('2')).toEqual({ left: 0, counted: 1 });
    expect(await run('30')).toEqual({ left: 1, counted: 0 });
  });

  it('the sharing worker drains quarantine jobs and records outcomes', async () => {
    e = await makeEnv();
    const owner = await e.register('worker@example.test');
    const tr = await e.call('POST', `${sp(owner.orgId)}/transfers`, {
      token: owner.token,
      body: { title: 'W', kind: 'temporary' },
    });
    await upload(
      e,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'w.pdf' },
      pdf('w'),
      { process: false },
    );
    const w = startSharingWorker(e.c, { everyMs: 3_600_000 });
    await w.runOnce();
    w.stop();
    expect(
      (await e.call('GET', `${sp(owner.orgId)}/transfers/${tr.body.id}`, { token: owner.token }))
        .body.files[0].status,
    ).toBe('available');
    expect(
      e.c.metrics.snapshot().counters['sharing_jobs_total{outcome="done"}'],
    ).toBeGreaterThanOrEqual(1);
  });
});
