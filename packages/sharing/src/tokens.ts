import { createHmac, randomBytes, randomInt } from 'node:crypto';
import { constantTimeEqual, sha256Hex } from '@trust/crypto';

/**
 * Secrets used by sharing. `secret` is operator configuration (SHARING_SECRET, >= 32 chars). Purpose-specific
 * keys are derived by HMAC labels so a leak of one derived value does not expose another purpose.
 */
export class SharingKeys {
  readonly #link: Buffer;
  readonly #grant: Buffer;
  constructor(secret: string) {
    if (secret.length < 32) throw new Error('sharing secret must be at least 32 characters');
    this.#link = createHmac('sha256', secret).update('rokela-sharing:link-token:v1').digest();
    this.#grant = createHmac('sha256', secret).update('rokela-sharing:grant:v1').digest();
  }

  /**
   * Unpredictable 256-bit URL token for a share link / upload request / confidential short link. It is derived
   * from the record id and a random salt under a server key, so the owner can see it again while a database
   * leak alone (which holds only the salt and the token's SHA-256) does not reveal it.
   */
  token(purpose: 'share' | 'request' | 'short', id: string, salt: string, length = 43): string {
    return createHmac('sha256', this.#link)
      .update(`${purpose}:${id}:${salt}`)
      .digest('base64url')
      .slice(0, length);
  }

  /** Short-lived, stateless access grant (issued after password/recipient checks; re-checked on every use). */
  grant(claims: GrantClaims): string {
    const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
    return `g1.${body}.${this.#sign(body)}`;
  }

  verifyGrant(token: string | undefined, nowMs: number): GrantClaims | undefined {
    if (!token || token.length > 1024) return undefined;
    const m = /^g1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(token);
    if (!m || !constantTimeEqual(this.#sign(m[1]!), m[2]!)) return undefined;
    let c: GrantClaims;
    try {
      c = JSON.parse(Buffer.from(m[1]!, 'base64url').toString('utf8')) as GrantClaims;
    } catch {
      return undefined;
    }
    if (typeof c.exp !== 'number' || c.exp * 1000 <= nowMs) return undefined;
    return c;
  }

  #sign(body: string): string {
    return createHmac('sha256', this.#grant).update(body).digest('base64url');
  }
}

export interface GrantClaims {
  /** Subject kind and id (share link or upload request). */
  k: 'share' | 'request';
  s: string;
  /** Authenticated user at grant time, if any. Re-validated against the current session on use. */
  u: string | null;
  /** Expiry, seconds since the epoch. */
  exp: number;
}

export const newSalt = () => randomBytes(16).toString('base64url');
export const tokenHash = (token: string) => sha256Hex(`sharing-token:${token}`);
/** Random submitter handle for upload requests (only its hash is stored). */
export const newSubmissionSecret = () => `sub_${randomBytes(32).toString('base64url')}`;
/** Random generated short code for PUBLIC links: 8 chars from an unambiguous alphabet (~41 bits, not a secret). */
export function newPublicCode(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  let out = '';
  // randomInt draws uniformly (no modulo bias).
  for (let i = 0; i < 8; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
}
