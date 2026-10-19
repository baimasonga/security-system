import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  counterAcceptable,
  decodeCbor,
  decodeCborExact,
  validateRelyingParty,
  verifyAssertion,
  verifyRegistration,
} from '../src/webauthn.ts';
import { encodeCbor, SoftAuthenticator, type Alg } from './soft-authenticator.ts';

const rp = { rpId: 'rokela.example', origin: 'https://app.rokela.example' };
const challenge = () => randomBytes(32).toString('base64url');
const d = (s: string) => Buffer.from(s, 'base64url');
const reg = (r: ReturnType<SoftAuthenticator['register']>) => ({
  clientDataJSON: d(r.response.clientDataJSON),
  attestationObject: d(r.response.attestationObject),
});
const asr = (r: ReturnType<SoftAuthenticator['assert']>) => ({
  clientDataJSON: d(r.response.clientDataJSON),
  authenticatorData: d(r.response.authenticatorData),
  signature: d(r.response.signature),
});

describe('WebAuthn registration and assertion', () => {
  for (const alg of [-8, -7, -257] as Alg[]) {
    it(`accepts a well-formed ${alg} credential and its assertions`, () => {
      const a = new SoftAuthenticator(alg, { counter: 5 });
      const ch = challenge();
      const r = verifyRegistration(reg(a.register(rp, ch)), rp);
      expect(r).toMatchObject({ challenge: ch, credentialId: a.id, signCount: 5 });
      expect(r.key.alg).toBe(alg);
      const ch2 = challenge();
      const out = verifyAssertion(asr(a.assert(rp, ch2, 'usr_1')), r.key, rp);
      expect(out).toMatchObject({ challenge: ch2, signCount: 6 });
    });
  }

  it('refuses registrations that break origin, RP, type, framing or user verification', () => {
    const a = new SoftAuthenticator(-7);
    const ch = challenge();
    const bad = {
      origin: { origin: 'https://evil.example' },
      'sub-origin': { origin: 'https://rokela.example' },
      rp: { rpId: 'evil.example' },
      type: { type: 'webauthn.get' },
      'cross-origin': { crossOrigin: true },
      'no UV': { flags: 0x41 },
      'no UP': { flags: 0x44 },
      'no attested data': { flags: 0x05 },
      'BS without BE': { flags: 0x55 },
      'short challenge': { challenge: 'abc' },
    };
    for (const [name, k] of Object.entries(bad))
      expect(() => verifyRegistration(reg(a.register(rp, ch, k)), rp), name).toThrow(/webauthn/);
  });

  it('refuses assertions with a bad signature, wrong RP/origin/type, or without user verification', () => {
    const a = new SoftAuthenticator(-7);
    const key = verifyRegistration(reg(a.register(rp, challenge())), rp).key;
    const other = verifyRegistration(
      reg(new SoftAuthenticator(-7).register(rp, challenge())),
      rp,
    ).key;
    const ch = challenge();
    expect(() => verifyAssertion(asr(a.assert(rp, ch, 'u')), other, rp)).toThrow(/signature/);
    for (const k of [
      { badSignature: true },
      { rpId: 'evil.example' },
      { origin: 'https://evil.example' },
      { type: 'webauthn.create' },
      { flags: 0x01 },
      { flags: 0x04 },
      { flags: 0x45 },
    ])
      expect(
        () => verifyAssertion(asr(a.assert(rp, ch, 'u', k)), key, rp),
        JSON.stringify(k),
      ).toThrow(/webauthn/);
  });

  it('applies the signature counter rule', () => {
    expect(counterAcceptable(0, 0)).toBe(true);
    expect(counterAcceptable(0, 1)).toBe(true);
    expect(counterAcceptable(5, 6)).toBe(true);
    expect(counterAcceptable(5, 5)).toBe(false);
    expect(counterAcceptable(5, 4)).toBe(false);
    expect(counterAcceptable(5, 0)).toBe(false);
  });
});

describe('bounded CBOR decoding', () => {
  it('round-trips the structures WebAuthn uses', () => {
    const v = new Map<number | string, unknown>([
      [1, 2],
      [-1, 1],
      ['fmt', 'none'],
      ['b', Buffer.from([1, 2, 3])],
      ['a', [true, false, null, 70000]],
    ]);
    const out = decodeCborExact(encodeCbor(v)) as Map<unknown, unknown>;
    expect(out.get(1)).toBe(2);
    expect(out.get(-1)).toBe(1);
    expect(out.get('fmt')).toBe('none');
    expect(Buffer.from(out.get('b') as Uint8Array)).toEqual(Buffer.from([1, 2, 3]));
    expect(out.get('a')).toEqual([true, false, null, 70000]);
  });

  it('rejects indefinite lengths, duplicate keys, trailing bytes, tags, deep nesting and truncation', () => {
    const cases: Record<string, Buffer> = {
      indefinite: Buffer.from([0x9f, 0x01, 0xff]),
      duplicate: Buffer.concat([
        Buffer.from([0xa2]),
        encodeCbor(1),
        encodeCbor(1),
        encodeCbor(1),
        encodeCbor(2),
      ]),
      trailing: Buffer.from([0x01, 0x02]),
      tag: Buffer.from([0xc1, 0x01]),
      deep: Buffer.from([...Array(20).fill(0x81), 0x01]),
      truncated: Buffer.from([0x58, 0x10, 0x01]),
      'huge array': Buffer.from([0x9a, 0xff, 0xff, 0xff, 0xff]),
      'bad utf8': Buffer.from([0x62, 0xc3, 0x28]),
      float: Buffer.from([0xf9, 0x3c, 0x00]),
    };
    for (const [name, b] of Object.entries(cases))
      expect(() => decodeCborExact(b), name).toThrow(/cbor/);
  });

  it('never crashes or hangs on random or truncated input (fuzz)', () => {
    const a = new SoftAuthenticator(-7);
    const good = d(a.register(rp, challenge()).response.attestationObject);
    for (let i = 0; i < 2000; i++) {
      const input =
        i % 2 === 0
          ? randomBytes(1 + (i % 64))
          : Buffer.from(
              good.map((b, j) => (j === i % good.length ? b ^ (1 << (i % 8)) : b)),
            ).subarray(0, good.length - (i % 7));
      try {
        decodeCbor(input);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
      try {
        verifyRegistration(
          {
            clientDataJSON: d(a.register(rp, challenge()).response.clientDataJSON),
            attestationObject: input,
          },
          rp,
        );
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });
});

describe('relying party configuration', () => {
  it('requires a domain RP ID and an https origin on it (http only for localhost in development)', () => {
    expect(validateRelyingParty(rp, true)).toEqual(rp);
    expect(
      validateRelyingParty({ rpId: 'localhost', origin: 'http://localhost:8080' }, false).rpId,
    ).toBe('localhost');
    const bad: Array<[string, string, boolean]> = [
      ['rokela.example', 'http://app.rokela.example', false],
      ['localhost', 'http://localhost:8080', true],
      ['rokela.example', 'https://app.other.example', true],
      ['rokela.example', 'https://evilrokela.example', true],
      ['rokela.example', 'https://app.rokela.example/', true],
      ['Rokela.Example', 'https://app.rokela.example', true],
      ['rokela.example', 'not a url', true],
    ];
    for (const [rpId, origin, prod] of bad)
      expect(() => validateRelyingParty({ rpId, origin }, prod), `${rpId} ${origin}`).toThrow(
        /WEBAUTHN/,
      );
  });
});
