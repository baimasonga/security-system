import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

// OWASP-aligned scrypt (N=2^15, r=8, p=1). Parameters are embedded in the hash so they can be raised
// later without invalidating stored hashes.
export const DEFAULT_SCRYPT: ScryptParams = { N: 32768, r: 8, p: 1 };
const KEYLEN = 32;

function derive(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  const opts: ScryptOptions = {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 256 * params.N * params.r,
  };
  return new Promise((resolve, reject) => {
    scrypt(password.normalize('NFKC'), salt, KEYLEN, opts, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

export async function hashPassword(
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT,
): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, params);
  return `scrypt$${params.N}$${params.r}$${params.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, keyB64] = parts as [string, string, string, string, string, string];
  const params = { N: Number(n), r: Number(r), p: Number(p) };
  if (![params.N, params.r, params.p].every((x) => Number.isInteger(x) && x > 0)) return false;
  if (params.N > 2 ** 20) return false; // refuse attacker-influenced resource blowups
  const expected = Buffer.from(keyB64, 'base64url');
  const actual = await derive(password, Buffer.from(saltB64, 'base64url'), params);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
