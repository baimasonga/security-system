import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

/** RFC 6238 interoperable authenticator profile: SHA-1, six digits, 30 seconds. */
export function totpCode(secret: Uint8Array, counter: number): string {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(bytes).digest();
  const offset = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}
export function matchingCounter(
  secret: Uint8Array,
  code: string,
  nowMs: number,
  lastCounter: number,
): number | undefined {
  if (!/^\d{6}$/.test(code)) return undefined;
  const current = Math.floor(nowMs / 30000);
  let match: number | undefined;
  for (const counter of [current - 1, current, current + 1]) {
    if (
      counter >= 0 &&
      counter > lastCounter &&
      timingSafeEqual(Buffer.from(totpCode(secret, counter)), Buffer.from(code))
    )
      match = counter;
  }
  return match;
}
export function base32(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0,
    value = 0,
    out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
/** Stable server-only key; AAD prevents moving a secret between user accounts. */
export class MfaCipher {
  readonly #key: Buffer;
  constructor(hexKey: string) {
    if (!/^[0-9a-f]{64}$/i.test(hexKey) || new Set(hexKey.toLowerCase()).size < 8)
      throw new Error('MFA_ENCRYPTION_KEY must be a random 32-byte hex key');
    this.#key = Buffer.from(hexKey, 'hex');
  }
  seal(userId: string, secret: Uint8Array): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(Buffer.from(`trust/mfa/v1/${userId}`));
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
  }
  open(userId: string, sealed: string): Buffer {
    try {
      const bytes = Buffer.from(sealed, 'base64url');
      if (bytes.length !== 48 || bytes.toString('base64url') !== sealed) throw new Error();
      const decipher = createDecipheriv('aes-256-gcm', this.#key, bytes.subarray(0, 12));
      decipher.setAAD(Buffer.from(`trust/mfa/v1/${userId}`));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]);
    } catch {
      throw new Error('MFA secret unavailable');
    }
  }
}
