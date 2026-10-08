import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacSha256Hex(key: string | Uint8Array, data: string): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Opaque, prefixed, unguessable identifier (96 bits). Identifiers are NOT secrets or authority. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('hex')}`;
}

/** 256-bit URL-safe secret for session tokens and challenge nonces. */
export function newSecretToken(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString('base64url')}`;
}

// Crockford base32 (no I, L, O, U); 25 chars = 125 bits of entropy.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Human-typable license key, 125 bits of entropy: `LK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`. */
export function generateLicenseKey(): string {
  const bytes = randomBytes(25);
  let out = '';
  for (const b of bytes) out += ALPHABET[b & 31];
  const groups = out.match(/.{1,5}/g) ?? [];
  return `LK-${groups.join('-')}`;
}

/** Case-insensitive; maps the visually ambiguous O→0 and I/L→1 in the key body (not the prefix). */
export function normalizeLicenseKey(input: string): string {
  const upper = input.trim().toUpperCase();
  const body = upper.startsWith('LK-') ? upper.slice(3) : upper;
  return `LK-${body.replace(/O/g, '0').replace(/[IL]/g, '1')}`;
}

/**
 * Digest under which a license key is stored/looked up. HMAC with a server-side pepper means a
 * database leak alone does not reveal usable keys, and keys cannot be brute-forced offline.
 */
export function licenseKeyDigest(pepper: string, key: string): string {
  return hmacSha256Hex(pepper, `license-key:${normalizeLicenseKey(key)}`);
}
