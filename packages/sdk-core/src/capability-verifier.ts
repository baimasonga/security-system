import { JwsError, verifyJws } from '@trust/crypto/verify';
import {
  CAPABILITY_TYP,
  MAX_CAPABILITY_TTL_SECONDS,
  audienceForService,
  type CapabilityClaims,
} from '@trust/shared-types';
import type { TrustBundle } from './lease-verifier.ts';

// Offline verification of capability tokens by processing services (ADR-024).

export type CapabilityRejection =
  | 'malformed'
  | 'bad_signature'
  | 'unknown_key'
  | 'bad_claims'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'wrong_capability'
  | 'wrong_device'
  | 'lifetime_too_long'
  | 'not_yet_valid'
  | 'expired';

export type CapabilityCheck =
  { ok: true; claims: CapabilityClaims } | { ok: false; reason: CapabilityRejection };

export interface VerifyCapabilityOptions {
  trust: TrustBundle;
  /** This service's name; the token's audience must be exactly `svc:<service>`. */
  service: string;
  /** The capability this request needs. */
  capability: string;
  now: Date;
  /** When the service knows the caller's device key (mutual TLS, request signature): its thumbprint. */
  deviceThumbprint?: string;
  issuer?: string;
}

const SKEW = 60;

function isClaims(c: unknown): c is CapabilityClaims {
  if (typeof c !== 'object' || c === null) return false;
  const o = c as Record<string, unknown>;
  const cnf = o['cnf'] as Record<string, unknown> | null | undefined;
  return (
    o['v'] === 1 &&
    ['iat', 'nbf', 'exp'].every((k) => Number.isInteger(o[k])) &&
    ['jti', 'iss', 'aud', 'sub', 'org', 'lic', 'prd', 'cap'].every(
      (k) => typeof o[k] === 'string',
    ) &&
    typeof cnf === 'object' &&
    cnf !== null &&
    typeof cnf['jkt'] === 'string'
  );
}

export function verifyCapabilityToken(token: string, o: VerifyCapabilityOptions): CapabilityCheck {
  let payload: unknown;
  try {
    payload = verifyJws(token, {
      typ: CAPABILITY_TYP,
      resolveKey: (kid) => o.trust.keys.find((k) => k.kid === kid)?.jwk,
    }).payload;
  } catch (e) {
    if (e instanceof JwsError) {
      if (e.reason === 'bad_signature') return { ok: false, reason: 'bad_signature' };
      if (e.reason === 'unknown_kid') return { ok: false, reason: 'unknown_key' };
    }
    return { ok: false, reason: 'malformed' };
  }
  if (!isClaims(payload)) return { ok: false, reason: 'bad_claims' };
  const c = payload;
  if (c.iss !== (o.issuer ?? 'trust-platform')) return { ok: false, reason: 'wrong_issuer' };
  if (c.aud !== audienceForService(o.service)) return { ok: false, reason: 'wrong_audience' };
  if (c.cap !== o.capability) return { ok: false, reason: 'wrong_capability' };
  if (o.deviceThumbprint !== undefined && c.cnf.jkt !== o.deviceThumbprint)
    return { ok: false, reason: 'wrong_device' };
  if (!(c.exp > c.iat) || c.nbf > c.exp) return { ok: false, reason: 'bad_claims' };
  if (c.exp - c.iat > MAX_CAPABILITY_TTL_SECONDS) return { ok: false, reason: 'lifetime_too_long' };
  const now = Math.floor(o.now.getTime() / 1000);
  if (now < c.nbf - SKEW) return { ok: false, reason: 'not_yet_valid' };
  if (now > c.exp + SKEW) return { ok: false, reason: 'expired' };
  return { ok: true, claims: c };
}
