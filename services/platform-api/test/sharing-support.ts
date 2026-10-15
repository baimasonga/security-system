import { expect } from 'vitest';
import { MemoryMailDelivery } from '../src/integrations/mail.ts';
import { DAY, makeEnv, type Env } from './harness.ts';

export const pdf = (text: string) => Buffer.from(`%PDF-1.7\n% ${text}\n%%EOF\n`, 'latin1');
export const UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36';

/** Paid plan entitlements that unlock every sharing feature (persistent sharing, requests, domains, branding). */
export const BUSINESS = {
  share_storage_bytes: 10 * 1024 ** 3,
  share_persistent: true,
  share_retention_days: 90,
  share_upload_requests: true,
  share_custom_domains: true,
  share_branding: true,
  share_advanced_analytics: true,
};

export interface SharingEnv extends Env {
  mail: MemoryMailDelivery;
}

export async function sharingEnv(): Promise<SharingEnv> {
  const mail = new MemoryMailDelivery();
  // Small parts make multipart behaviour (resume, missing parts) testable with tiny files.
  const env = await makeEnv({
    identityDelivery: mail,
    container: { sharingConfig: { partBytes: 8 }, sharingMailer: mail },
  });
  return Object.assign(env, { mail });
}

/** Operator grants the organization a subscription plan with the given entitlements. */
export async function grantPlan(
  env: Env,
  orgId: string,
  entitlements: Record<string, number | boolean>,
  code = 'business',
) {
  const token = await env.operatorToken();
  const reason = 'test provisioning';
  let prod = await env.call('POST', '/v1/admin/products', {
    token,
    body: { code: `pdf-pro-${code}`, name: 'PDF Pro', reason },
  });
  expect(prod.status).toBe(201);
  const plan = await env.call('POST', `/v1/admin/products/${prod.body.id}/plans`, {
    token,
    body: { code, tier: 'business', entitlements, capabilities: [], device_limit: 3, reason },
  });
  const sub = await env.call('POST', `/v1/admin/organizations/${orgId}/subscriptions`, {
    token,
    body: {
      plan_id: plan.body.id,
      status: 'active',
      current_period_end: new Date(env.clock.now().getTime() + 365 * DAY).toISOString(),
      reason,
    },
  });
  const lic = await env.call('POST', `/v1/admin/organizations/${orgId}/licenses`, {
    token,
    body: {
      product_id: prod.body.id,
      plan_id: plan.body.id,
      kind: 'subscription',
      subscription_id: sub.body.id,
      reason,
    },
  });
  expect(lic.status).toBe(201);
  prod = lic;
  return lic.body.license.id as string;
}

export const sp = (orgId: string) => `/v1/organizations/${orgId}/sharing`;

/** Full owner upload: begin → signed part PUTs to the content origin → complete → quarantine jobs. */
export async function upload(
  env: Env,
  token: string,
  orgId: string,
  body: Record<string, unknown>,
  bytes: Buffer,
  opts: { process?: boolean; skipParts?: number[] } = {},
) {
  const begin = await env.call('POST', `${sp(orgId)}/uploads`, {
    token,
    body: { ...body, size: bytes.length },
  });
  if (begin.status !== 201) return { begin };
  const id = begin.body.upload_id as string;
  const nums = Array.from({ length: begin.body.part_count as number }, (_, i) => i + 1);
  const signed = await env.call('POST', `${sp(orgId)}/uploads/${id}/parts`, {
    token,
    body: { part_numbers: nums },
  });
  expect(signed.status).toBe(200);
  const size = begin.body.part_size as number;
  for (const p of signed.body.parts as Array<{ part_number: number; url: string }>) {
    if (opts.skipParts?.includes(p.part_number)) continue;
    const chunk = bytes.subarray((p.part_number - 1) * size, p.part_number * size);
    const put = await env.content('PUT', p.url, chunk, {
      origin: env.c.config.sharing!.publicOrigin,
    });
    expect(put.status, `part ${p.part_number}`).toBe(200);
  }
  if (opts.skipParts?.length) return { begin, id };
  const complete = await env.call('POST', `${sp(orgId)}/uploads/${id}/complete`, {
    token,
    body: {},
  });
  expect(complete.status).toBe(200);
  if (opts.process !== false) await env.c.sharing!.processJobs({ limit: 100 });
  return { begin, id, complete };
}

/** Fetches a signed download URL from the content origin. */
export async function fetchSigned(env: Env, url: string) {
  return env.content('GET', url);
}

export const tokenOf = (url: string) => new URL(url).pathname.split('/').pop()!;

export async function verifyEmail(env: SharingEnv, token: string) {
  expect((await env.call('POST', '/v1/auth/email/request', { token, body: {} })).status).toBe(202);
  await env.c.auth.flushIdentityMail();
  const t = env.mail.messages.at(-1)!.text.match(/#verify=(recover_[A-Za-z0-9_-]+)/)![1]!;
  expect((await env.call('POST', '/v1/auth/email/verify', { body: { token: t } })).status).toBe(
    204,
  );
}
