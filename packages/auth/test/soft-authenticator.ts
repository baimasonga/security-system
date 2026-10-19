// A software WebAuthn authenticator for tests: produces registration (fmt "none") and assertion responses exactly as
// a browser would hand them to the server, with knobs to break each property the server must check.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

export function encodeCbor(v: unknown): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') {
    const s = Buffer.from(v, 'utf8');
    return Buffer.concat([head(3, s.length), s]);
  }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(encodeCbor)]);
  if (v instanceof Map)
    return Buffer.concat([
      head(5, v.size),
      ...[...v.entries()].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)]),
    ]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  if (v === null) return Buffer.from([0xf6]);
  throw new Error('unsupported');
}

const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest();
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

export type Alg = -8 | -7 | -257;

export interface Knobs {
  origin?: string;
  rpId?: string;
  type?: string;
  challenge?: string;
  /** Flags byte override (default UP|UV, plus AT for registration). */
  flags?: number;
  counter?: number;
  crossOrigin?: boolean;
  badSignature?: boolean;
  userHandle?: string | null;
}

export class SoftAuthenticator {
  readonly alg: Alg;
  readonly credentialId: Buffer;
  readonly #priv: KeyObject;
  readonly #pub: KeyObject;
  counter: number;

  constructor(alg: Alg = -7, opts?: { counter?: number }) {
    this.alg = alg;
    this.credentialId = randomBytes(32);
    const pair =
      alg === -8
        ? generateKeyPairSync('ed25519')
        : alg === -7
          ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
          : generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.#priv = pair.privateKey;
    this.#pub = pair.publicKey;
    this.counter = opts?.counter ?? 0;
  }

  get id(): string {
    return b64u(this.credentialId);
  }

  coseKey(): Map<number, unknown> {
    const jwk = this.#pub.export({ format: 'jwk' }) as Record<string, string>;
    const d = (s: string) => Buffer.from(s, 'base64url');
    if (this.alg === -8)
      return new Map<number, unknown>([
        [1, 1],
        [3, -8],
        [-1, 6],
        [-2, d(jwk['x']!)],
      ]);
    if (this.alg === -7)
      return new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, d(jwk['x']!)],
        [-3, d(jwk['y']!)],
      ]);
    return new Map<number, unknown>([
      [1, 3],
      [3, -257],
      [-1, d(jwk['n']!)],
      [-2, d(jwk['e']!)],
    ]);
  }

  #clientData(type: string, challenge: string, k: Knobs, origin: string): Buffer {
    return Buffer.from(
      JSON.stringify({
        type: k.type ?? type,
        challenge: k.challenge ?? challenge,
        origin: k.origin ?? origin,
        ...(k.crossOrigin !== undefined ? { crossOrigin: k.crossOrigin } : {}),
      }),
    );
  }

  #authData(rpId: string, flags: number, counter: number, attested?: Buffer): Buffer {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    return Buffer.concat([sha(rpId), Buffer.from([flags]), c, ...(attested ? [attested] : [])]);
  }

  /** What `navigator.credentials.create()` returns (JSON form, base64url). */
  register(
    rp: { rpId: string; origin: string },
    challenge: string,
    k: Knobs = {},
  ): {
    id: string;
    rawId: string;
    type: 'public-key';
    response: { clientDataJSON: string; attestationObject: string };
  } {
    const len = Buffer.from([this.credentialId.length >> 8, this.credentialId.length & 255]);
    const attested = Buffer.concat([
      Buffer.alloc(16),
      len,
      this.credentialId,
      encodeCbor(this.coseKey()),
    ]);
    const authData = this.#authData(
      k.rpId ?? rp.rpId,
      k.flags ?? 0x45,
      k.counter ?? this.counter,
      attested,
    );
    const att = encodeCbor(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(this.#clientData('webauthn.create', challenge, k, rp.origin)),
        attestationObject: b64u(att),
      },
    };
  }

  /** What `navigator.credentials.get()` returns (JSON form, base64url). Increments the counter unless it is 0. */
  assert(
    rp: { rpId: string; origin: string },
    challenge: string,
    userHandle: string,
    k: Knobs = {},
  ): {
    id: string;
    rawId: string;
    type: 'public-key';
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
  } {
    if (this.counter > 0 && k.counter === undefined) this.counter++;
    const authData = this.#authData(k.rpId ?? rp.rpId, k.flags ?? 0x05, k.counter ?? this.counter);
    const clientData = this.#clientData('webauthn.get', challenge, k, rp.origin);
    const data = Buffer.concat([authData, sha(clientData)]);
    let sig = this.alg === -8 ? sign(null, data, this.#priv) : sign('sha256', data, this.#priv);
    if (k.badSignature) sig = Buffer.from(sig.map((b, i) => (i === 10 ? b ^ 1 : b)));
    const handle = k.userHandle === undefined ? userHandle : k.userHandle;
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientData),
        authenticatorData: b64u(authData),
        signature: b64u(sig),
        ...(handle !== null ? { userHandle: b64u(Buffer.from(handle)) } : {}),
      },
    };
  }
}
