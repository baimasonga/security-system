import { createHash, createPublicKey, timingSafeEqual, verify, type KeyObject } from 'node:crypto';

// WebAuthn Relying Party checks (ADR-023). Pure functions: no storage, no clock. Attestation is never trusted.

// ---- bounded CBOR decoder (RFC 8949 subset: definite lengths only) -------------------------------------------

export type Cbor =
  number | bigint | string | Uint8Array | boolean | null | undefined | Cbor[] | CborMap;
export type CborMap = Map<number | string, Cbor>;

const MAX_ITEMS = 256;
const MAX_DEPTH = 8;

class CborError extends Error {}

/** Decodes one CBOR item starting at `offset`; returns it and the offset just after it. */
export function decodeCbor(bytes: Uint8Array, offset = 0, depth = 0): { value: Cbor; end: number } {
  if (depth > MAX_DEPTH) throw new CborError('cbor: too deep');
  const need = (n: number) => {
    if (offset + n > bytes.length) throw new CborError('cbor: truncated');
  };
  need(1);
  const head = bytes[offset++]!;
  const major = head >> 5;
  const info = head & 31;
  let arg: number;
  if (info < 24) arg = info;
  else if (info === 24) {
    need(1);
    arg = bytes[offset++]!;
  } else if (info === 25) {
    need(2);
    arg = (bytes[offset]! << 8) | bytes[offset + 1]!;
    offset += 2;
  } else if (info === 26) {
    need(4);
    arg =
      ((bytes[offset]! << 24) >>> 0) +
      (bytes[offset + 1]! << 16) +
      (bytes[offset + 2]! << 8) +
      bytes[offset + 3]!;
    offset += 4;
  } else if (info === 27) {
    need(8);
    const big = new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0);
    offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('cbor: integer too large');
    arg = Number(big);
  } else throw new CborError('cbor: unsupported length encoding'); // 28-30 reserved, 31 indefinite

  switch (major) {
    case 0:
      return { value: arg, end: offset };
    case 1:
      return { value: -1 - arg, end: offset };
    case 2: {
      need(arg);
      return { value: bytes.slice(offset, offset + arg), end: offset + arg };
    }
    case 3: {
      need(arg);
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(
          bytes.subarray(offset, offset + arg),
        );
      } catch {
        throw new CborError('cbor: invalid utf-8');
      }
      return { value: text, end: offset + arg };
    }
    case 4: {
      if (arg > MAX_ITEMS) throw new CborError('cbor: array too long');
      const out: Cbor[] = [];
      for (let i = 0; i < arg; i++) {
        const r = decodeCbor(bytes, offset, depth + 1);
        out.push(r.value);
        offset = r.end;
      }
      return { value: out, end: offset };
    }
    case 5: {
      if (arg > MAX_ITEMS) throw new CborError('cbor: map too large');
      const out: CborMap = new Map();
      for (let i = 0; i < arg; i++) {
        const k = decodeCbor(bytes, offset, depth + 1);
        if (typeof k.value !== 'number' && typeof k.value !== 'string')
          throw new CborError('cbor: unsupported map key');
        if (out.has(k.value)) throw new CborError('cbor: duplicate map key');
        const v = decodeCbor(bytes, k.end, depth + 1);
        out.set(k.value, v.value);
        offset = v.end;
      }
      return { value: out, end: offset };
    }
    case 7:
      if (info === 20) return { value: false, end: offset };
      if (info === 21) return { value: true, end: offset };
      if (info === 22) return { value: null, end: offset };
      if (info === 23) return { value: undefined, end: offset };
      throw new CborError('cbor: unsupported simple value');
    default:
      throw new CborError('cbor: unsupported type'); // tags (6) are not used by WebAuthn
  }
}

/** Decodes exactly one item spanning the whole input. */
export function decodeCborExact(bytes: Uint8Array): Cbor {
  const r = decodeCbor(bytes);
  if (r.end !== bytes.length) throw new CborError('cbor: trailing bytes');
  return r.value;
}

// ---- COSE keys ------------------------------------------------------------------------------------------------

/** Supported COSE algorithms: EdDSA (Ed25519), ES256 (P-256), RS256. */
export const COSE_ALGS = [-8, -7, -257] as const;
export type CoseAlg = (typeof COSE_ALGS)[number];

export interface StoredKey {
  alg: CoseAlg;
  /** Public key as JWK (no private members). */
  jwk: Record<string, string>;
}

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const bytesOf = (v: Cbor | undefined, len?: number): Uint8Array => {
  if (!(v instanceof Uint8Array) || (len !== undefined && v.length !== len))
    throw new Error('webauthn: malformed key');
  return v;
};

export function coseToStoredKey(cose: Cbor): StoredKey {
  if (!(cose instanceof Map)) throw new Error('webauthn: malformed key');
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (alg === -8 && kty === 1 && cose.get(-1) === 6) {
    return { alg, jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(bytesOf(cose.get(-2), 32)) } };
  }
  if (alg === -7 && kty === 2 && cose.get(-1) === 1) {
    return {
      alg,
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: b64u(bytesOf(cose.get(-2), 32)),
        y: b64u(bytesOf(cose.get(-3), 32)),
      },
    };
  }
  if (alg === -257 && kty === 3) {
    const n = bytesOf(cose.get(-1));
    if (n.length < 256 || n.length > 512) throw new Error('webauthn: unsupported RSA key size');
    return { alg, jwk: { kty: 'RSA', n: b64u(n), e: b64u(bytesOf(cose.get(-2))) } };
  }
  throw new Error('webauthn: unsupported algorithm');
}

function keyObject(k: StoredKey): KeyObject {
  return createPublicKey({ key: k.jwk, format: 'jwk' });
}

export function verifySignature(k: StoredKey, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    const key = keyObject(k);
    if (k.alg === -8) return verify(null, data, key, signature);
    // ES256 signatures are DER-encoded in WebAuthn; RS256 is PKCS#1 v1.5.
    return verify('sha256', data, key, signature);
  } catch {
    return false;
  }
}

// ---- authenticator data -----------------------------------------------------------------------------------------

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  credential?: { id: Uint8Array; key: StoredKey };
}

export function parseAuthData(a: Uint8Array): AuthData {
  if (a.length < 37) throw new Error('webauthn: authenticator data too short');
  const flags = a[32]!;
  const signCount = new DataView(a.buffer, a.byteOffset + 33, 4).getUint32(0);
  const out: AuthData = { rpIdHash: a.slice(0, 32), flags, signCount };
  let offset = 37;
  if (flags & FLAG_AT) {
    if (a.length < offset + 18) throw new Error('webauthn: attested data too short');
    offset += 16; // AAGUID: not trusted, not stored
    const idLen = (a[offset]! << 8) | a[offset + 1]!;
    offset += 2;
    if (idLen < 16 || idLen > 1023 || a.length < offset + idLen)
      throw new Error('webauthn: bad credential id');
    const id = a.slice(offset, offset + idLen);
    offset += idLen;
    const key = decodeCbor(a, offset);
    offset = key.end;
    out.credential = { id, key: coseToStoredKey(key.value) };
  }
  if (flags & FLAG_ED) offset = decodeCbor(a, offset).end;
  if (offset !== a.length) throw new Error('webauthn: trailing authenticator data');
  return out;
}

// ---- client data ------------------------------------------------------------------------------------------------

export interface RelyingParty {
  rpId: string;
  origin: string;
}

const MAX_CLIENT_DATA = 4096;

/** Checks clientDataJSON; returns the challenge it carries (base64url) when type, origin and framing are right. */
export function checkClientData(
  raw: Uint8Array,
  type: 'webauthn.create' | 'webauthn.get',
  rp: RelyingParty,
): string {
  if (raw.length > MAX_CLIENT_DATA) throw new Error('webauthn: client data too large');
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as Record<
      string,
      unknown
    >;
  } catch {
    throw new Error('webauthn: client data is not JSON');
  }
  if (c['type'] !== type) throw new Error('webauthn: wrong ceremony type');
  if (c['origin'] !== rp.origin) throw new Error('webauthn: wrong origin');
  if (c['crossOrigin'] === true) throw new Error('webauthn: cross-origin ceremony');
  const challenge = c['challenge'];
  if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge))
    throw new Error('webauthn: bad challenge');
  return challenge;
}

export const sha256 = (b: Uint8Array | string) => createHash('sha256').update(b).digest();

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---- ceremonies -------------------------------------------------------------------------------------------------

export interface RegistrationResult {
  credentialId: string;
  key: StoredKey;
  signCount: number;
  backupEligible: boolean;
  backedUp: boolean;
}

/** Verifies a registration response (WebAuthn L2 §7.1, without attestation trust). Returns the challenge too. */
export function verifyRegistration(
  input: { clientDataJSON: Uint8Array; attestationObject: Uint8Array },
  rp: RelyingParty,
): RegistrationResult & { challenge: string } {
  const challenge = checkClientData(input.clientDataJSON, 'webauthn.create', rp);
  if (input.attestationObject.length > 16384) throw new Error('webauthn: attestation too large');
  const att = decodeCborExact(input.attestationObject);
  if (!(att instanceof Map)) throw new Error('webauthn: malformed attestation');
  const fmt = att.get('fmt');
  const authDataBytes = att.get('authData');
  if (
    typeof fmt !== 'string' ||
    !(authDataBytes instanceof Uint8Array) ||
    !(att.get('attStmt') instanceof Map)
  )
    throw new Error('webauthn: malformed attestation');
  const ad = parseAuthData(authDataBytes);
  if (!sameBytes(ad.rpIdHash, sha256(rp.rpId))) throw new Error('webauthn: wrong relying party');
  if (!(ad.flags & FLAG_UP) || !(ad.flags & FLAG_UV))
    throw new Error('webauthn: user not verified');
  if (!ad.credential) throw new Error('webauthn: no credential');
  if (!(ad.flags & FLAG_BE) && ad.flags & FLAG_BS)
    throw new Error('webauthn: inconsistent backup flags');
  return {
    challenge,
    credentialId: b64u(ad.credential.id),
    key: ad.credential.key,
    signCount: ad.signCount,
    backupEligible: (ad.flags & FLAG_BE) !== 0,
    backedUp: (ad.flags & FLAG_BS) !== 0,
  };
}

/** Verifies an assertion (WebAuthn L2 §7.2) against a stored key. Returns the challenge and the new counter. */
export function verifyAssertion(
  input: { clientDataJSON: Uint8Array; authenticatorData: Uint8Array; signature: Uint8Array },
  key: StoredKey,
  rp: RelyingParty,
): { challenge: string; signCount: number; backedUp: boolean } {
  const challenge = checkClientData(input.clientDataJSON, 'webauthn.get', rp);
  if (input.authenticatorData.length > 4096 || input.signature.length > 1024)
    throw new Error('webauthn: oversized assertion');
  const ad = parseAuthData(input.authenticatorData);
  if (ad.credential) throw new Error('webauthn: unexpected attested data');
  if (!sameBytes(ad.rpIdHash, sha256(rp.rpId))) throw new Error('webauthn: wrong relying party');
  if (!(ad.flags & FLAG_UP) || !(ad.flags & FLAG_UV))
    throw new Error('webauthn: user not verified');
  const signed = Buffer.concat([input.authenticatorData, sha256(input.clientDataJSON)]);
  if (!verifySignature(key, signed, input.signature)) throw new Error('webauthn: bad signature');
  return { challenge, signCount: ad.signCount, backedUp: (ad.flags & FLAG_BS) !== 0 };
}

/** Signature counter rule: if either counter is non-zero, the new one must be strictly greater. */
export function counterAcceptable(stored: number, next: number): boolean {
  return stored === 0 && next === 0 ? true : next > stored;
}

/** `WEBAUTHN_ORIGIN` must be the RP ID or a subdomain of it; production needs https. */
export function validateRelyingParty(rp: RelyingParty, production: boolean): RelyingParty {
  const label = (l: string) =>
    l.length >= 1 &&
    l.length <= 63 &&
    /^[a-z0-9-]+$/.test(l) &&
    !l.startsWith('-') &&
    !l.endsWith('-');
  if (rp.rpId.length < 1 || rp.rpId.length > 253 || !rp.rpId.split('.').every(label))
    throw new Error('WEBAUTHN_RP_ID must be a lowercase domain name');
  let u: URL;
  try {
    u = new URL(rp.origin);
  } catch {
    throw new Error('WEBAUTHN_ORIGIN must be an origin such as https://app.example.com');
  }
  if (u.origin !== rp.origin)
    throw new Error('WEBAUTHN_ORIGIN must be an origin (no path or trailing slash)');
  if (u.protocol !== 'https:' && (production || u.hostname !== 'localhost'))
    throw new Error('WEBAUTHN_ORIGIN must use https (http only for localhost in development)');
  if (u.hostname !== rp.rpId && !u.hostname.endsWith(`.${rp.rpId}`))
    throw new Error('WEBAUTHN_ORIGIN must be on WEBAUTHN_RP_ID or one of its subdomains');
  return rp;
}
