import { afterEach, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { totpCode } from '../../../packages/auth/src/mfa.ts';
import { makeEnv, PW, type Env } from './harness.ts';
import { loadConfig, type PlatformConfig } from '../src/config.ts';
import { MemoryMailDelivery, type TransactionalMessage } from '../src/integrations/mail.ts';
let env: Env;
afterEach(async () => env?.app.close());
const MFA_KEY = randomBytes(32).toString('hex');
const ACCOUNT = 'a'.repeat(32);
const ORIGIN = 'https://warrior.example.test';
const ops = {
  operationsInventoryEnabled: true,
  operationsCredentialsEnabled: true,
  operationsIngestionEnabled: true,
  operationsHealthEnabled: true,
  operationsIncidentsEnabled: true,
  operationsAutomationEnabled: true,
};
function decode(value: string) {
  let bits = 0,
    n = 0;
  const out: number[] = [];
  for (const c of value) {
    n = (n << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((n >>> bits) & 255);
    }
  }
  return Buffer.from(out);
}
/** A provider that refuses every message, as a provider outage does. */
class DownMail {
  attempts = 0;
  async send(): Promise<{ id: string }> {
    this.attempts++;
    throw new Error('email delivery unavailable');
  }
}
async function setup(opts: {
  email: boolean;
  verify?: boolean;
  mail?: { send(m: TransactionalMessage): Promise<{ id: string }> };
}) {
  const identity = new MemoryMailDelivery(),
    alerts = opts.mail ?? new MemoryMailDelivery();
  const config: Partial<PlatformConfig> = {
    ...ops,
    mfaEncryptionKey: MFA_KEY,
    operationsEmailNotificationsEnabled: opts.email,
    emailDelivery: {
      provider: 'cloudflare',
      accountId: ACCOUNT,
      apiToken: 'synthetic',
      from: 'Warrior <alerts@example.test>',
      publicOrigin: ORIGIN,
    },
  };
  env = await makeEnv({
    config,
    identityDelivery: identity,
    container: { operationsMail: alerts },
  });
  const owner = await env.register('owner@example.test');
  if (opts.verify !== false) {
    expect(
      (await env.call('POST', '/v1/auth/email/request', { token: owner.token, body: {} })).status,
    ).toBe(202);
    await env.c.auth.flushIdentityMail();
    const t = identity.messages.at(-1)!.text.match(/#verify=(recover_[A-Za-z0-9_-]+)/)![1]!;
    expect((await env.call('POST', '/v1/auth/email/verify', { body: { token: t } })).status).toBe(
      204,
    );
  }
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const app = await env.call('POST', base, {
    token: owner.token,
    body: {
      code: 'rokela-pdf',
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  const environment = await env.call('POST', base + '/' + app.body.id + '/environments', {
    token: owner.token,
    body: { code: 'production', kind: 'production', reason: 'initial_setup' },
  });
  const envPath = base + '/' + app.body.id + '/environments/' + environment.body.id;
  const component = await env.call('POST', envPath + '/components', {
    token: owner.token,
    body: { code: 'api', kind: 'service', dependency_ids: [], reason: 'initial_setup' },
  });
  expect(component.status).toBe(201);
  // Credentials need fresh MFA; enroll and sign in again with it.
  const begin = await env.call('POST', '/v1/auth/mfa/begin', {
    token: owner.token,
    body: { password: PW },
  });
  const secret = decode(begin.body.setup_key);
  const current = () => totpCode(secret, Math.floor(+env.clock.now() / 30000));
  await env.call('POST', '/v1/auth/mfa/confirm', {
    token: owner.token,
    body: { password: PW, code: current() },
  });
  env.clock.advance(30000);
  const login = await env.call('POST', '/v1/auth/login', {
    body: { email: 'owner@example.test', password: PW, code: current() },
  });
  owner.token = login.body.token;
  env.clock.advance(30000);
  const issued = await env.call('POST', envPath + '/credentials', {
    token: owner.token,
    body: {
      purpose: 'events:write',
      ttl_seconds: 86400,
      reason: 'initial_setup',
      mfa_code: current(),
    },
  });
  expect(issued.status).toBe(201);
  const rule = await env.call('POST', envPath + '/rules', {
    token: owner.token,
    body: {
      component_id: component.body.id,
      kind: 'heartbeat',
      event_type: null,
      threshold: 1,
      window_seconds: 60,
      severity: 'critical',
      runbook: 'investigate_component',
      reason: 'initial_setup',
    },
  });
  expect(rule.status).toBe(201);
  const heartbeat = async () => {
    const r = await env.call('POST', '/v1/operations/events', {
      token: issued.body.token,
      body: {
        schema: 1,
        events: [
          {
            id: randomUUID(),
            component_id: component.body.id,
            occurred_at: env.clock.now().toISOString(),
            type: 'component.heartbeat',
            attributes: { status: 'healthy' },
          },
        ],
      },
    });
    expect(r.status).toBe(200);
  };
  const scope = {
    orgId: owner.orgId,
    applicationId: app.body.id as string,
    environmentId: environment.body.id as string,
  };
  const tick = () => env.c.operationsAutomation.tick().catch(() => {});
  const notifications = async () =>
    (await env.call('GET', envPath + '/notifications', { token: owner.token })).body.items as {
      transition: string;
      state: string;
      attempts: number;
    }[];
  // Sessions expire during long simulated outages; sign in again with MFA.
  const relogin = async () => {
    env.clock.advance(30000);
    owner.token = (
      await env.call('POST', '/v1/auth/login', {
        body: { email: 'owner@example.test', password: PW, code: current() },
      })
    ).body.token;
  };
  return { owner, scope, heartbeat, tick, notifications, alerts, relogin };
}
/** Healthy, then silent long enough to breach (180 s stale) and to fill the 60 s window. */
async function goSilent(f: Awaited<ReturnType<typeof setup>>) {
  await f.heartbeat();
  await f.tick();
  env.clock.advance(180000);
  await f.tick();
  env.clock.advance(60000);
  await f.tick();
}
it('requires automation and a configured provider before email notifications can start', () => {
  const base = {
    NODE_ENV: 'test',
    OPERATIONS_INVENTORY_ENABLED: 'true',
    OPERATIONS_INGESTION_ENABLED: 'true',
    OPERATIONS_HEALTH_ENABLED: 'true',
    OPERATIONS_INCIDENTS_ENABLED: 'true',
    OPERATIONS_AUTOMATION_ENABLED: 'true',
  };
  const mail = {
    MAIL_PROVIDER: 'cloudflare',
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
    CLOUDFLARE_EMAIL_API_TOKEN: 'synthetic',
    EMAIL_FROM: 'Warrior <alerts@example.test>',
    PUBLIC_ORIGIN: ORIGIN,
  };
  expect(loadConfig(base).operationsEmailNotificationsEnabled).toBe(false);
  expect(() => loadConfig({ ...base, OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED: 'true' })).toThrow(
    'requires automation and an email provider',
  );
  expect(() =>
    loadConfig({
      ...mail,
      NODE_ENV: 'test',
      OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED: 'true',
    }),
  ).toThrow('requires automation and an email provider');
  expect(() =>
    loadConfig({ ...base, ...mail, OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED: 'yes' }),
  ).toThrow('true or false');
  const on = loadConfig({ ...base, ...mail, OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED: 'true' });
  expect(on.operationsEmailNotificationsEnabled).toBe(true);
  expect(on.emailDelivery).toEqual({
    provider: 'cloudflare',
    accountId: ACCOUNT,
    apiToken: 'synthetic',
    from: 'Warrior <alerts@example.test>',
    publicOrigin: ORIGIN,
  });
});
it('selects a complete email provider and refuses ambiguous or partial settings', () => {
  const t = { NODE_ENV: 'test', EMAIL_FROM: 'alerts@example.test', PUBLIC_ORIGIN: ORIGIN };
  const cf = { CLOUDFLARE_ACCOUNT_ID: ACCOUNT, CLOUDFLARE_EMAIL_API_TOKEN: 'synthetic' };
  expect(loadConfig({ NODE_ENV: 'test' }).emailDelivery).toBeUndefined();
  // Cloudflare settings alone never activate email; the provider is chosen explicitly.
  expect(loadConfig({ NODE_ENV: 'test', ...cf }).emailDelivery).toBeUndefined();
  expect(loadConfig({ ...t, ...cf, MAIL_PROVIDER: 'cloudflare' }).emailDelivery?.provider).toBe(
    'cloudflare',
  );
  expect(loadConfig({ ...t, RESEND_API_KEY: 'synthetic' }).emailDelivery?.provider).toBe('resend');
  expect(loadConfig({ ...t, ...cf, RESEND_API_KEY: 'synthetic' }).emailDelivery?.provider).toBe(
    'resend',
  );
  expect(
    loadConfig({ ...t, ...cf, RESEND_API_KEY: 'synthetic', MAIL_PROVIDER: 'resend' }).emailDelivery
      ?.provider,
  ).toBe('resend');
  expect(() => loadConfig({ ...t, ...cf, MAIL_PROVIDER: 'smtp' })).toThrow('resend or cloudflare');
  expect(() =>
    loadConfig({ ...t, MAIL_PROVIDER: 'cloudflare', ...cf, CLOUDFLARE_ACCOUNT_ID: 'x' }),
  ).toThrow('CLOUDFLARE_ACCOUNT_ID');
  expect(() =>
    loadConfig({ ...t, MAIL_PROVIDER: 'cloudflare', CLOUDFLARE_ACCOUNT_ID: ACCOUNT }),
  ).toThrow('CLOUDFLARE_EMAIL_API_TOKEN');
  expect(() => loadConfig({ ...t, MAIL_PROVIDER: 'resend' })).toThrow('RESEND_API_KEY');
  expect(() => loadConfig({ NODE_ENV: 'test', ...cf, MAIL_PROVIDER: 'cloudflare' })).toThrow(
    'EMAIL_FROM and PUBLIC_ORIGIN',
  );
});
it('emails the verified rule creator when a silent component opens an incident, and again on recovery', async () => {
  const f = await setup({ email: true });
  const alerts = f.alerts as MemoryMailDelivery;
  await goSilent(f);
  expect(alerts.messages).toHaveLength(1);
  const [opened] = alerts.messages;
  expect(opened!.to).toBe('owner@example.test');
  expect(opened!.subject).toBe('Warrior incident opened: critical on rokela-pdf/production/api');
  expect(opened!.text).toContain('Runbook: investigate_component');
  expect(opened!.text).toContain(`Review it in Warrior: ${ORIGIN}/`);
  expect(opened!.id).toMatch(/^opn_/);
  expect((await f.notifications()).map((n) => [n.transition, n.state])).toEqual([
    ['opened', 'delivered'],
  ]);
  await f.heartbeat();
  await f.tick();
  env.clock.advance(60000);
  await f.heartbeat();
  await f.tick();
  expect(alerts.messages.map((m) => m.subject)).toEqual([
    'Warrior incident opened: critical on rokela-pdf/production/api',
    'Warrior incident resolved on rokela-pdf/production/api',
  ]);
  // Repeated ticks never resend a delivered notification.
  await f.tick();
  expect(alerts.messages).toHaveLength(2);
});
it('keeps portal-only delivery when the flag is off', async () => {
  const f = await setup({ email: false });
  await goSilent(f);
  expect((f.alerts as MemoryMailDelivery).messages).toEqual([]);
  expect((await f.notifications()).map((n) => [n.transition, n.state])).toEqual([
    ['opened', 'delivered'],
  ]);
});
it('never emails an unverified address and leaves the failure visible for retry', async () => {
  const f = await setup({ email: true, verify: false });
  await goSilent(f);
  expect((f.alerts as MemoryMailDelivery).messages).toEqual([]);
  const [n] = await f.notifications();
  expect(n).toMatchObject({ transition: 'opened', state: 'pending', attempts: 1 });
});
it('retries a provider outage with backoff and gives up visibly after the deadline', async () => {
  const down = new DownMail();
  const f = await setup({ email: true, mail: down });
  await goSilent(f);
  expect(down.attempts).toBe(1);
  expect((await f.notifications())[0]).toMatchObject({ state: 'pending', attempts: 1 });
  // Backoff: an immediate tick does not retry.
  await f.tick();
  expect(down.attempts).toBe(1);
  env.clock.advance(2000);
  await f.tick();
  expect(down.attempts).toBe(2);
  env.clock.advance(73 * 3600000);
  await f.tick();
  await f.relogin();
  expect((await f.notifications())[0]?.state).toBe('failed');
  const attempts = down.attempts;
  env.clock.advance(3600000);
  await f.tick();
  expect(down.attempts).toBe(attempts);
});
