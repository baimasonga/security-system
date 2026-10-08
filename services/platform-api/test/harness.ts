import type { FastifyInstance } from 'fastify';
import { buildApp, type AppOptions } from '../src/app.ts';
import { loadConfig, type PlatformConfig } from '../src/config.ts';
import { createContainer, type Container } from '../src/container.ts';
import type { LicensingConfig } from '@trust/licensing';

export const DAY = 86_400_000;
export const PW = 'correct horse battery staple';

export interface Env {
  app: FastifyInstance;
  c: Container;
  clock: { now: () => Date; set: (d: Date) => void; advance: (ms: number) => void };
  call: (
    method: string,
    url: string,
    opts?: { token?: string; body?: unknown; headers?: Record<string, string> },
  ) => Promise<{ status: number; body: any; headers: Record<string, unknown> }>;
  register: (email: string) => Promise<{ userId: string; orgId: string; token: string }>;
  login: (email: string) => Promise<string>;
  operatorToken: () => Promise<string>;
  /** Operator creates the standard catalog + a subscription-backed license for `orgId`. */
  provision: (
    orgId: string,
    over?: { deviceLimit?: number },
  ) => Promise<{
    productId: string;
    planId: string;
    subId: string;
    licenseId: string;
    licenseKey: string;
  }>;
}

export async function makeEnv(over?: {
  config?: Partial<PlatformConfig>;
  licensing?: Partial<LicensingConfig>;
  app?: AppOptions;
}): Promise<Env> {
  let t = new Date('2026-03-01T00:00:00Z');
  const clock = {
    now: () => t,
    set: (d: Date) => void (t = d),
    advance: (ms: number) => void (t = new Date(t.getTime() + ms)),
  };
  const config: PlatformConfig = {
    ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv),
    scrypt: { N: 1024, r: 8, p: 1 },
    rateLimits: {
      global: 100_000,
      login: 100_000,
      register: 100_000,
      challenge: 100_000,
      activate: 100_000,
    },
    ...over?.config,
  };
  const c = createContainer(config, {
    clock,
    ...(over?.licensing ? { licensing: over.licensing } : {}),
  });
  const app = await buildApp(c, over?.app);
  await app.ready();

  const call: Env['call'] = async (method, url, opts) => {
    const res = await app.inject({
      method: method as 'GET',
      url,
      headers: {
        ...(opts?.token ? { authorization: `Bearer ${opts.token}` } : {}),
        ...opts?.headers,
      },
      ...(opts?.body !== undefined ? { payload: opts.body as object } : {}),
    });
    let body: unknown = undefined;
    try {
      body = res.body ? JSON.parse(res.body) : undefined;
    } catch {
      body = res.body;
    }
    return { status: res.statusCode, body, headers: res.headers };
  };

  const login = async (email: string) =>
    (await call('POST', '/v1/auth/login', { body: { email, password: PW } })).body.token as string;
  const register: Env['register'] = async (email) => {
    const r = await call('POST', '/v1/auth/register', { body: { email, password: PW } });
    if (r.status !== 201) throw new Error(`register failed ${r.status} ${JSON.stringify(r.body)}`);
    return { userId: r.body.user.id, orgId: r.body.personal_org.id, token: await login(email) };
  };

  let opToken: string | undefined;
  const operatorToken = async () => {
    if (opToken) return opToken;
    await register('operator@example.test');
    await c.auth.bootstrapPlatformAdmin('operator@example.test');
    return (opToken = await login('operator@example.test'));
  };

  const provision: Env['provision'] = async (orgId, o) => {
    const token = await operatorToken();
    const reason = 'test provisioning';
    const prod = await call('POST', '/v1/admin/products', {
      token,
      body: { code: 'pdf-pro', name: 'PDF Pro', reason },
    });
    if (prod.status === 409) throw new Error('provision twice in one env is not supported');
    const productId = prod.body.id as string;
    const plan = await call('POST', `/v1/admin/products/${productId}/plans`, {
      token,
      body: {
        code: 'professional',
        tier: 'professional',
        entitlements: { pdf_editing: true, ocr_pages_monthly: 5000 },
        capabilities: ['OCR_ADVANCED', 'CLOUD_SYNC'],
        device_limit: o?.deviceLimit ?? 3,
        reason,
      },
    });
    const sub = await call('POST', `/v1/admin/organizations/${orgId}/subscriptions`, {
      token,
      body: {
        plan_id: plan.body.id,
        status: 'active',
        current_period_end: new Date(t.getTime() + 30 * DAY).toISOString(),
        reason,
      },
    });
    const lic = await call('POST', `/v1/admin/organizations/${orgId}/licenses`, {
      token,
      body: {
        product_id: productId,
        plan_id: plan.body.id,
        kind: 'subscription',
        subscription_id: sub.body.id,
        reason,
      },
    });
    if (lic.status !== 201)
      throw new Error(`license issue failed ${lic.status} ${JSON.stringify(lic.body)}`);
    return {
      productId,
      planId: plan.body.id,
      subId: sub.body.id,
      licenseId: lic.body.license.id,
      licenseKey: lic.body.license_key,
    };
  };

  return { app, c, clock, call, register, login, operatorToken, provision };
}
