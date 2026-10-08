import { z } from 'zod';
import { SUBSCRIPTION_STATUSES } from '@trust/licensing';
import { ORG_ROLES, TIERS } from '@trust/shared-types';

const str = (max: number) => z.string().min(1).max(max);
const id = z.string().regex(/^[a-z]{2,4}_[0-9a-f]{24}$/);
const date = z.string().datetime();
const reason = z.string().min(3).max(500);

export const registerBody = z
  .object({ email: str(254), password: z.string().min(1).max(256) })
  .strict();
export const loginBody = registerBody;
export const orgBody = z.object({ name: str(200) }).strict();
export const memberBody = z.object({ email: str(254), role: z.enum(ORG_ROLES) }).strict();
export const orgParams = z.object({ orgId: id }).strict();
export const licenseParams = z.object({ orgId: id, licenseId: id }).strict();
export const activationParams = z.object({ orgId: id, activationId: id }).strict();
export const trialBody = z.object({ product_id: id }).strict();
export const entitlementsQuery = z.object({ org_id: id, license_id: id }).strict();

const entitlementValue = z.union([z.boolean(), z.number()]);
const overrides = z
  .object({
    entitlements: z.record(z.union([entitlementValue, z.null()])).optional(),
    capabilities: z
      .object({
        add: z.array(str(64)).max(100).optional(),
        remove: z.array(str(64)).max(100).optional(),
      })
      .strict()
      .optional(),
    device_limit: z.number().int().optional(),
  })
  .strict();

export const challengeBody = z
  .object({
    purpose: z.enum(['activate', 'validate', 'refresh', 'deactivate']),
    installation_id: str(64),
    subject_id: str(64).optional(),
  })
  .strict();

export const activateBody = z
  .object({
    license_key: str(64),
    installation_id: str(64),
    device_public_key: z
      .object({ kty: z.literal('OKP'), crv: z.literal('Ed25519'), x: str(64) })
      .strict(),
    nonce: str(128),
    signature: str(128),
  })
  .strict();

export const deviceAuthBody = z
  .object({
    activation_id: str(64),
    installation_id: str(64),
    nonce: str(128),
    signature: str(128),
  })
  .strict();

// ---- operator -------------------------------------------------------------------------------
export const productBody = z.object({ code: str(64), name: str(200), reason }).strict();
export const planBody = z
  .object({
    code: str(64),
    tier: z.enum(TIERS),
    entitlements: z.record(entitlementValue).default({}),
    capabilities: z.array(str(64)).max(100).default([]),
    device_limit: z.number().int(),
    reason,
  })
  .strict();
export const planPatchBody = z
  .object({
    entitlements: z.record(entitlementValue).optional(),
    capabilities: z.array(str(64)).max(100).optional(),
    device_limit: z.number().int().optional(),
    reason,
  })
  .strict();
export const subscriptionBody = z
  .object({
    plan_id: id,
    status: z.enum(SUBSCRIPTION_STATUSES),
    trial_end: date.optional(),
    current_period_end: date.optional(),
    reason,
  })
  .strict();
export const subscriptionPatchBody = z
  .object({
    plan_id: id.optional(),
    status: z.enum(SUBSCRIPTION_STATUSES).optional(),
    current_period_end: date.nullable().optional(),
    reason,
  })
  .strict();
export const issueLicenseBody = z
  .object({
    product_id: id,
    plan_id: id,
    kind: z.enum(['subscription', 'trial', 'perpetual', 'canary']),
    subscription_id: id.optional(),
    expires_at: date.optional(),
    overrides: overrides.optional(),
    reason,
  })
  .strict();
export const reasonBody = z.object({ reason }).strict();
export const auditQuery = z
  .object({
    org_id: id.optional(),
    action: str(100).optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
  })
  .strict();
export const auditVerifyQuery = z.object({ org_id: id.optional() }).strict();
export const anchorsQuery = z
  .object({ limit: z.coerce.number().int().min(1).max(200).default(20) })
  .strict();
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
/** A manifest as published to the witness. Large logs: check with tools/verify-anchor.ts instead. */
export const anchorManifestBody = z
  .object({
    manifest: z
      .object({
        v: z.literal(1),
        created_at: z.string().max(40),
        anchor: hex64,
        chains: z
          .array(
            z
              .object({
                chain: z.string().min(1).max(300),
                seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
                hash: hex64,
              })
              .strict(),
          )
          .max(5000),
      })
      .strict(),
  })
  .strict();
export const planParams = z.object({ planId: id }).strict();
export const productParams = z.object({ productId: id }).strict();
export const subParams = z.object({ orgId: id, subscriptionId: id }).strict();
export const adminLicenseParams = licenseParams;

export function mapOverrides(o: z.infer<typeof overrides> | undefined) {
  if (!o) return undefined;
  return {
    ...(o.entitlements ? { entitlements: o.entitlements } : {}),
    ...(o.capabilities ? { capabilities: o.capabilities } : {}),
    ...(o.device_limit !== undefined ? { deviceLimit: o.device_limit } : {}),
  };
}

export const metricsQuery = z
  .object({ format: z.enum(['json', 'prometheus']).default('json') })
  .strict();
