import type { Tier } from '@trust/shared-types';

// Entitlement resolution is a PURE function: (plan version, per-license overrides) → resolved facts.
// Clients never see plan names as rules; they receive the resolved snapshot inside a signed lease.

export type EntitlementValue = boolean | number;

export interface PlanDefinition {
  id: string;
  productId: string;
  code: string;
  tier: Tier;
  /** Monotonic; bumped on every change so refreshed leases can carry the new snapshot. */
  version: number;
  entitlements: Record<string, EntitlementValue>;
  capabilities: string[];
  deviceLimit: number;
}

export interface EntitlementOverrides {
  /** `null` removes an entitlement granted by the plan. */
  entitlements?: Record<string, EntitlementValue | null>;
  capabilities?: { add?: string[]; remove?: string[] };
  deviceLimit?: number;
}

export interface ResolvedEntitlements {
  planId: string;
  planVersion: number;
  tier: Tier;
  entitlements: Record<string, EntitlementValue>;
  /** Sorted, de-duplicated. */
  capabilities: string[];
  deviceLimit: number;
}

export const ENTITLEMENT_KEY = /^[a-z][a-z0-9_]{0,63}$/;
export const CAPABILITY_KEY = /^[A-Z][A-Z0-9_]{0,63}$/;
export const MAX_ENTRIES = 100;
/** ASCII ent/cap JSON budget; leaves room for binding claims within the 16 KiB compact JWS limit. */
export const MAX_ENTITLEMENT_SNAPSHOT_BYTES = 8 * 1024;
export const MAX_DEVICE_LIMIT = 10_000;

export class EntitlementValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EntitlementValidationError';
  }
}

export function validateEntitlementMap(
  map: Record<string, unknown>,
): Record<string, EntitlementValue> {
  const keys = Object.keys(map);
  if (keys.length > MAX_ENTRIES) throw new EntitlementValidationError('too many entitlements');
  const out: Record<string, EntitlementValue> = {};
  for (const k of keys) {
    if (!ENTITLEMENT_KEY.test(k))
      throw new EntitlementValidationError(`invalid entitlement key: ${k}`);
    const v = map[k];
    if (typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 2 ** 40) out[k] = v;
    else throw new EntitlementValidationError(`invalid entitlement value for ${k}`);
  }
  return out;
}

export function validateCapabilities(caps: readonly string[]): string[] {
  if (caps.length > MAX_ENTRIES) throw new EntitlementValidationError('too many capabilities');
  for (const c of caps) {
    if (!CAPABILITY_KEY.test(c)) throw new EntitlementValidationError(`invalid capability: ${c}`);
  }
  return [...new Set(caps)].sort();
}

export function validateDeviceLimit(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > MAX_DEVICE_LIMIT) {
    throw new EntitlementValidationError('device limit out of range');
  }
  return n;
}

/** Apply after validating the ASCII keys/values and after merging overrides. */
export function validateEntitlementSnapshot(
  entitlements: Record<string, EntitlementValue>,
  capabilities: readonly string[],
): void {
  if (
    JSON.stringify({ ent: entitlements, cap: capabilities }).length > MAX_ENTITLEMENT_SNAPSHOT_BYTES
  )
    throw new EntitlementValidationError('entitlement snapshot exceeds lease size budget');
}

export function resolveEntitlements(
  plan: PlanDefinition,
  overrides?: EntitlementOverrides,
): ResolvedEntitlements {
  const entitlements: Record<string, EntitlementValue> = { ...plan.entitlements };
  for (const [k, v] of Object.entries(overrides?.entitlements ?? {})) {
    if (!ENTITLEMENT_KEY.test(k))
      throw new EntitlementValidationError(`invalid entitlement key: ${k}`);
    if (v === null) delete entitlements[k];
    else entitlements[k] = validateEntitlementMap({ [k]: v })[k]!;
  }
  const caps = new Set(plan.capabilities);
  for (const c of overrides?.capabilities?.add ?? []) caps.add(c);
  for (const c of overrides?.capabilities?.remove ?? []) caps.delete(c);
  const capabilities = validateCapabilities([...caps]);
  validateEntitlementSnapshot(entitlements, capabilities);
  return {
    planId: plan.id,
    planVersion: plan.version,
    tier: plan.tier,
    entitlements: Object.fromEntries(
      Object.entries(entitlements).sort(([a], [b]) => a.localeCompare(b)),
    ),
    capabilities,
    deviceLimit: validateDeviceLimit(overrides?.deviceLimit ?? plan.deviceLimit),
  };
}

export function hasCapability(r: Pick<ResolvedEntitlements, 'capabilities'>, cap: string): boolean {
  return r.capabilities.includes(cap);
}
