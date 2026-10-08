// Verification-only entrypoint. This is the ONLY part of @trust/crypto that client SDKs may import
// (enforced by tools/check-boundaries.mjs). It contains no code that can use a signing key.
import { verify as edVerify } from 'node:crypto';
import { b64urlDecode } from './encoding.ts';
import { isPublicJwk, publicKeyObject, type PublicJwk } from './jwk.ts';

export { b64urlDecode, b64urlEncode, canonicalJson } from './encoding.ts';
export { isPublicJwk, jwkThumbprint, normalizePublicJwk } from './jwk.ts';
export type { PublicJwk } from './jwk.ts';

export const MAX_JWS_BYTES = 16 * 1024;

export interface JwsHeader {
  alg: 'EdDSA';
  typ: string;
  kid: string;
}

export interface VerifiedJws<T> {
  header: JwsHeader;
  payload: T;
}

export type JwsFailure =
  | 'malformed'
  | 'too_large'
  | 'bad_header'
  | 'bad_alg'
  | 'bad_typ'
  | 'unknown_kid'
  | 'bad_signature';

export class JwsError extends Error {
  readonly reason: JwsFailure;
  constructor(reason: JwsFailure) {
    super(`jws verification failed: ${reason}`);
    this.name = 'JwsError';
    this.reason = reason;
  }
}

export interface VerifyJwsOptions {
  typ: string;
  /** Return the public key for a kid ONLY if that key is currently allowed to verify. */
  resolveKey: (kid: string) => PublicJwk | undefined;
}

/**
 * Verify a compact JWS. Algorithm is pinned to EdDSA (no negotiation, no "none"); the key is
 * chosen by `kid` from a caller-provided allow-list, never from the token itself.
 */
export function verifyJws<T = Record<string, unknown>>(
  token: string,
  opts: VerifyJwsOptions,
): VerifiedJws<T> {
  if (typeof token !== 'string') throw new JwsError('malformed');
  if (token.length > MAX_JWS_BYTES) throw new JwsError('too_large');
  const parts = token.split('.');
  if (parts.length !== 3) throw new JwsError('malformed');
  const [h, p, s] = parts as [string, string, string];

  let headerObj: unknown;
  let payloadObj: unknown;
  let sig: Buffer;
  try {
    headerObj = JSON.parse(b64urlDecode(h).toString('utf8'));
    payloadObj = JSON.parse(b64urlDecode(p).toString('utf8'));
    sig = b64urlDecode(s);
  } catch {
    throw new JwsError('malformed');
  }
  if (typeof headerObj !== 'object' || headerObj === null) throw new JwsError('bad_header');
  const header = headerObj as Record<string, unknown>;
  if (header['alg'] !== 'EdDSA') throw new JwsError('bad_alg');
  if (header['typ'] !== opts.typ) throw new JwsError('bad_typ');
  if (typeof header['kid'] !== 'string' || header['kid'].length === 0 || header['kid'].length > 128)
    throw new JwsError('bad_header');
  if (typeof payloadObj !== 'object' || payloadObj === null || Array.isArray(payloadObj))
    throw new JwsError('malformed');

  const jwk = opts.resolveKey(header['kid']);
  if (!jwk || !isPublicJwk(jwk)) throw new JwsError('unknown_kid');
  if (sig.length !== 64) throw new JwsError('bad_signature');
  const ok = edVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), publicKeyObject(jwk), sig);
  if (!ok) throw new JwsError('bad_signature');
  return {
    header: { alg: 'EdDSA', typ: opts.typ, kid: header['kid'] },
    payload: payloadObj as T,
  };
}

/** Raw Ed25519 signature check (used for device proof-of-possession). Never throws. */
export function verifySignature(jwk: PublicJwk, message: string, signatureB64u: string): boolean {
  try {
    const sig = b64urlDecode(signatureB64u);
    if (sig.length !== 64) return false;
    return edVerify(null, Buffer.from(message, 'utf8'), publicKeyObject(jwk), sig);
  } catch {
    return false;
  }
}

export type ProofPurpose = 'activate' | 'validate' | 'refresh' | 'deactivate';

/**
 * Domain-separated message a device signs to answer a challenge. Binding purpose, installation,
 * subject and key thumbprint prevents cross-purpose and cross-installation replay.
 * This string format is a wire contract shared by server and every SDK.
 */
export function buildProofMessage(p: {
  purpose: ProofPurpose;
  nonce: string;
  installationId: string;
  /** '' for `activate` (license is resolved from the key); the activation id for other purposes. */
  subjectId: string;
  thumbprint: string;
}): string {
  return [
    'trust-platform/v1/device-proof',
    p.purpose,
    p.nonce,
    p.installationId,
    p.subjectId,
    p.thumbprint,
  ].join('\n');
}
