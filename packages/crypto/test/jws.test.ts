import { describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import {
  JwsError,
  KeyRing,
  SoftwareKeyCustody,
  b64urlEncode,
  buildProofMessage,
  canonicalJson,
  generateEd25519,
  jwkThumbprint,
  signJws,
  verifyJws,
  verifySignature,
} from '../src/index.ts';
import { sign } from 'node:crypto';

async function setup() {
  const ring = new KeyRing();
  const k = ring.generate('license');
  ring.activate(k.kid);
  const token = await signJws({ hello: 'world' }, { typ: 'lease+jws', kid: k.kid }, ring.custody);
  const resolveKey = (kid: string) => ring.resolveVerificationKey('license', kid);
  return { ring, k, token, resolveKey };
}

function reason(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return e instanceof JwsError ? e.reason : 'other';
  }
  return undefined;
}

describe('JWS (EdDSA only)', () => {
  it('round-trips a signed payload', async () => {
    const { token, resolveKey } = await setup();
    const v = verifyJws<{ hello: string }>(token, { typ: 'lease+jws', resolveKey });
    expect(v.payload.hello).toBe('world');
    expect(v.header.alg).toBe('EdDSA');
  });

  it('rejects a tampered payload', async () => {
    const { token, resolveKey } = await setup();
    const [h, , s] = token.split('.') as [string, string, string];
    const forged = `${h}.${b64urlEncode(JSON.stringify({ hello: 'admin' }))}.${s}`;
    expect(reason(() => verifyJws(forged, { typ: 'lease+jws', resolveKey }))).toBe('bad_signature');
  });

  it('rejects a tampered signature', async () => {
    const { token, resolveKey } = await setup();
    const parts = token.split('.');
    const sig = Buffer.from(parts[2]!, 'base64url');
    sig[0] = sig[0]! ^ 0xff;
    parts[2] = sig.toString('base64url');
    expect(reason(() => verifyJws(parts.join('.'), { typ: 'lease+jws', resolveKey }))).toBe(
      'bad_signature',
    );
  });

  it('rejects alg=none and HMAC downgrade attempts', async () => {
    const { k, resolveKey } = await setup();
    const payload = b64urlEncode(JSON.stringify({ hello: 'world' }));
    const none = b64urlEncode(JSON.stringify({ alg: 'none', typ: 'lease+jws', kid: k.kid }));
    expect(reason(() => verifyJws(`${none}.${payload}.`, { typ: 'lease+jws', resolveKey }))).toBe(
      'bad_alg',
    );
    // classic alg-confusion: HS256 using the public key bytes as the HMAC secret
    const hs = b64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'lease+jws', kid: k.kid }));
    const mac = createHmac('sha256', k.publicJwk.x).update(`${hs}.${payload}`).digest('base64url');
    expect(
      reason(() => verifyJws(`${hs}.${payload}.${mac}`, { typ: 'lease+jws', resolveKey })),
    ).toBe('bad_alg');
  });

  it('rejects unknown kid and wrong typ', async () => {
    const { token, resolveKey } = await setup();
    expect(reason(() => verifyJws(token, { typ: 'other+jws', resolveKey }))).toBe('bad_typ');
    expect(reason(() => verifyJws(token, { typ: 'lease+jws', resolveKey: () => undefined }))).toBe(
      'unknown_kid',
    );
  });

  it('rejects a signature made by a different key under the same kid', async () => {
    const { k, resolveKey } = await setup();
    const attacker = generateEd25519();
    const h = b64urlEncode(JSON.stringify({ alg: 'EdDSA', typ: 'lease+jws', kid: k.kid }));
    const p = b64urlEncode(JSON.stringify({ hello: 'world' }));
    const sig = sign(null, Buffer.from(`${h}.${p}`), attacker.privateKey).toString('base64url');
    expect(reason(() => verifyJws(`${h}.${p}.${sig}`, { typ: 'lease+jws', resolveKey }))).toBe(
      'bad_signature',
    );
  });

  it.each(['', 'a.b', 'a.b.c.d', '....', 'x'.repeat(20000)])(
    'rejects malformed token %#',
    async (t) => {
      const { resolveKey } = await setup();
      expect(reason(() => verifyJws(t, { typ: 'lease+jws', resolveKey }))).toBeDefined();
    },
  );

  it('rejects non-canonical base64url (padding) in any segment', async () => {
    const { token, resolveKey } = await setup();
    const [h, p, s] = token.split('.') as [string, string, string];
    expect(reason(() => verifyJws(`${h}.${p}=.${s}`, { typ: 'lease+jws', resolveKey }))).toBe(
      'malformed',
    );
  });
});

describe('device proof of possession', () => {
  it('verifies a signature over the domain-separated proof message only', () => {
    const dev = generateEd25519();
    const base = {
      purpose: 'activate' as const,
      nonce: 'n1',
      installationId: 'inst_1',
      subjectId: 'act_1',
      thumbprint: jwkThumbprint(dev.publicJwk),
    };
    const msg = buildProofMessage(base);
    const sig = sign(null, Buffer.from(msg), dev.privateKey).toString('base64url');
    expect(verifySignature(dev.publicJwk, msg, sig)).toBe(true);
    // changing purpose, nonce, installation or license invalidates the proof
    for (const delta of [
      { purpose: 'refresh' as const },
      { nonce: 'n2' },
      { installationId: 'inst_2' },
      { subjectId: 'act_2' },
    ]) {
      expect(verifySignature(dev.publicJwk, buildProofMessage({ ...base, ...delta }), sig)).toBe(
        false,
      );
    }
    expect(verifySignature(generateEd25519().publicJwk, msg, sig)).toBe(false);
    expect(verifySignature(dev.publicJwk, msg, 'not-a-signature')).toBe(false);
  });
});

describe('canonicalJson / thumbprint', () => {
  it('is order independent and rejects non-finite numbers', () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] })).toBe('{"a":[2,{"c":2,"d":1}],"b":1}');
    expect(() => canonicalJson({ a: NaN })).toThrow();
  });
  it('thumbprint ignores private/extra members', () => {
    const { publicJwk } = generateEd25519();
    expect(jwkThumbprint({ ...publicJwk, d: 'secret', kid: 'x' } as never)).toBe(
      jwkThumbprint(publicJwk),
    );
  });
});

describe('KeyRing lifecycle', () => {
  it('cannot sign until activated; signing fails closed with no active key', async () => {
    const ring = new KeyRing();
    ring.generate('license');
    expect(() => ring.activeKeyId('license')).toThrow(/no active/);
  });

  it('rotation: new key active, old key deprecated but still verifies', async () => {
    const events: string[] = [];
    const ring = new KeyRing({ onEvent: (e) => events.push(`${e.action}:${e.to}`) });
    const a = ring.generate('license');
    ring.activate(a.kid);
    const tokenA = await signJws({ n: 1 }, { typ: 't', kid: a.kid }, ring.custody);
    const b = ring.generate('license');
    ring.activate(b.kid);
    expect(ring.get(a.kid)?.state).toBe('deprecated');
    expect(ring.activeKeyId('license')).toBe(b.kid);
    const resolveKey = (kid: string) => ring.resolveVerificationKey('license', kid);
    expect(verifyJws(tokenA, { typ: 't', resolveKey }).payload).toEqual({ n: 1 });
    expect(
      ring
        .trustBundle('license')
        .keys.map((k) => k.kid)
        .sort(),
    ).toEqual([a.kid, b.kid].sort());
    expect(events).toContain('deprecate:deprecated');
  });

  it('emergency revocation of an online key removes it from verification and the bundle', async () => {
    const ring = new KeyRing();
    const a = ring.generate('license');
    ring.activate(a.kid);
    const token = await signJws({}, { typ: 't', kid: a.kid }, ring.custody);
    ring.revoke(a.kid, 'suspected compromise');
    const resolveKey = (kid: string) => ring.resolveVerificationKey('license', kid);
    expect(reason(() => verifyJws(token, { typ: 't', resolveKey }))).toBe('unknown_kid');
    expect(ring.trustBundle('license').keys).toEqual([]);
    expect(() => ring.activeKeyId('license')).toThrow();
  });

  it('rejects illegal transitions and destroys private material', async () => {
    const ring = new KeyRing();
    const a = ring.generate('license');
    expect(() => ring.revoke(a.kid, 'x')).toThrow(/illegal/);
    ring.activate(a.kid);
    expect(() => ring.archive(a.kid)).toThrow(/illegal/);
    ring.deprecate(a.kid);
    ring.revoke(a.kid, 'r');
    ring.destroy(a.kid, 'cleanup');
    await expect(ring.custody.sign(a.kid, Buffer.from('x'))).rejects.toThrow();
    expect(() => ring.activate(a.kid)).toThrow(/illegal/);
  });

  it('trust bundle never contains private members', () => {
    const ring = new KeyRing();
    const a = ring.generate('license');
    ring.activate(a.kid);
    expect(JSON.stringify(ring.trustBundle('license'))).not.toMatch(/"d"\s*:/);
  });

  it('imports PEM key material and rejects non-Ed25519', () => {
    const ring = new KeyRing();
    const { privateKey } = generateEd25519();
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const rec = ring.importPrivateKeyPem('license', pem, 'imported-1');
    expect(rec.kid).toBe('imported-1');
    expect(() => new KeyRing().importPrivateKeyPem('license', 'garbage')).toThrow();
    expect(new SoftwareKeyCustody().has('x')).toBe(false);
  });
});
