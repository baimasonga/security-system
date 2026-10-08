import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';
import { b64urlDecode, b64urlEncode, canonicalJson } from './encoding.ts';

/** The only key type the platform accepts: Ed25519 public keys in JWK (RFC 8037) form. */
export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export function isPublicJwk(v: unknown): v is PublicJwk {
  if (typeof v !== 'object' || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o['kty'] !== 'OKP' || o['crv'] !== 'Ed25519' || typeof o['x'] !== 'string') return false;
  try {
    return b64urlDecode(o['x']).length === 32;
  } catch {
    return false;
  }
}

/** Return a normalized copy containing only the public members (drops `d`, `kid`, etc.). */
export function normalizePublicJwk(v: unknown): PublicJwk {
  if (!isPublicJwk(v)) throw new Error('invalid Ed25519 public JWK');
  return { kty: 'OKP', crv: 'Ed25519', x: v.x };
}

/** RFC 7638-style thumbprint: base64url(SHA-256(canonical required members)). */
export function jwkThumbprint(jwk: PublicJwk): string {
  const j = normalizePublicJwk(jwk);
  return b64urlEncode(
    createHash('sha256')
      .update(canonicalJson({ crv: j.crv, kty: j.kty, x: j.x }))
      .digest(),
  );
}

export function publicKeyObject(jwk: PublicJwk): KeyObject {
  return createPublicKey({ key: normalizePublicJwk(jwk) as JsonWebKey, format: 'jwk' });
}

export function generateEd25519(): { publicJwk: PublicJwk; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicJwk: normalizePublicJwk(publicKey.export({ format: 'jwk' })), privateKey };
}
