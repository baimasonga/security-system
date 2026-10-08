import { JwsError, verifyJws, type PublicJwk } from '@trust/crypto/verify';
import { LEASE_TYP, audienceForProduct, type LeaseClaims } from '@trust/shared-types';

export interface TrustBundleKey {
  kid: string;
  jwk: PublicJwk;
  state?: 'active' | 'deprecated';
}
export interface TrustBundle {
  schema: 1;
  keys: TrustBundleKey[];
}

/**
 * Offline lease states. The SDK reports state; the HOST APPLICATION decides how to degrade.
 * No state authorizes deleting or locking user documents: `expired`/`invalid` should map to a
 * documented restricted mode (e.g. view/export only), never data loss.
 */
export type LeaseState = 'valid' | 'refresh_recommended' | 'expired' | 'clock_anomaly' | 'invalid';

export type LeaseInvalidReason =
  | 'malformed'
  | 'bad_signature'
  | 'unknown_key'
  | 'bad_claims'
  | 'wrong_issuer'
  | 'wrong_product'
  | 'wrong_installation'
  | 'wrong_device'
  | 'not_yet_valid';

export type LeaseCheck =
  | { state: 'valid' | 'refresh_recommended'; claims: LeaseClaims; nextLastSeenAt: Date }
  | { state: 'expired'; claims: LeaseClaims; nextLastSeenAt: Date }
  | { state: 'clock_anomaly'; claims: LeaseClaims; nextLastSeenAt: Date }
  | { state: 'invalid'; reason: LeaseInvalidReason };

export interface VerifyLeaseOptions {
  /** Pinned/loaded public verification material. Contains no secrets. */
  trust: TrustBundle;
  productCode: string;
  installationId: string;
  /** Thumbprint of THIS device's public key. */
  deviceThumbprint: string;
  now: Date;
  /** Monotonic high-water mark the host persisted from previous checks (anti clock-rollback). */
  lastSeenAt?: Date | undefined;
  issuer?: string;
  /** Tolerated clock disagreement in seconds. Bounded: values above 1 hour are clamped. */
  skewSeconds?: number;
}

const MAX_SKEW = 3600;

function isClaims(c: unknown): c is LeaseClaims {
  if (typeof c !== 'object' || c === null) return false;
  const o = c as Record<string, unknown>;
  const nums = ['iat', 'nbf', 'exp', 'refresh_after', 'plv', 'dl'];
  const strs = [
    'jti',
    'iss',
    'aud',
    'lic',
    'org',
    'prd',
    'pln',
    'act',
    'inst',
    'dev',
    'kind',
    'tier',
  ];
  return (
    o['v'] === 1 &&
    nums.every((k) => typeof o[k] === 'number' && Number.isFinite(o[k])) &&
    strs.every((k) => typeof o[k] === 'string') &&
    typeof o['cnf'] === 'object' &&
    o['cnf'] !== null &&
    typeof (o['cnf'] as Record<string, unknown>)['jkt'] === 'string' &&
    typeof o['ent'] === 'object' &&
    o['ent'] !== null &&
    Array.isArray(o['cap'])
  );
}

export function verifyLease(token: string, opts: VerifyLeaseOptions): LeaseCheck {
  let claims: unknown;
  try {
    claims = verifyJws(token, {
      typ: LEASE_TYP,
      resolveKey: (kid) => opts.trust.keys.find((k) => k.kid === kid)?.jwk,
    }).payload;
  } catch (e) {
    if (e instanceof JwsError) {
      if (e.reason === 'bad_signature') return { state: 'invalid', reason: 'bad_signature' };
      if (e.reason === 'unknown_kid') return { state: 'invalid', reason: 'unknown_key' };
    }
    return { state: 'invalid', reason: 'malformed' };
  }
  if (!isClaims(claims)) return { state: 'invalid', reason: 'bad_claims' };
  if (claims.iss !== (opts.issuer ?? 'trust-platform'))
    return { state: 'invalid', reason: 'wrong_issuer' };
  if (claims.aud !== audienceForProduct(opts.productCode))
    return { state: 'invalid', reason: 'wrong_product' };
  if (claims.inst !== opts.installationId)
    return { state: 'invalid', reason: 'wrong_installation' };
  if (claims.cnf.jkt !== opts.deviceThumbprint) return { state: 'invalid', reason: 'wrong_device' };
  if (!(claims.exp > claims.iat) || claims.nbf > claims.exp)
    return { state: 'invalid', reason: 'bad_claims' };

  const skew = Math.min(Math.max(opts.skewSeconds ?? 300, 0), MAX_SKEW);
  const nowS = Math.floor(opts.now.getTime() / 1000);
  const lastS = opts.lastSeenAt ? Math.floor(opts.lastSeenAt.getTime() / 1000) : undefined;
  const nextLastSeenAt = new Date(Math.max(opts.now.getTime(), opts.lastSeenAt?.getTime() ?? 0));

  // Clock moved backwards relative to what we have already seen, or lease is from the "future".
  if ((lastS !== undefined && nowS < lastS - skew) || nowS < claims.nbf - skew) {
    return { state: 'clock_anomaly', claims, nextLastSeenAt };
  }
  if (nowS > claims.exp + skew) return { state: 'expired', claims, nextLastSeenAt };
  if (nowS >= claims.refresh_after) return { state: 'refresh_recommended', claims, nextLastSeenAt };
  return { state: 'valid', claims, nextLastSeenAt };
}
