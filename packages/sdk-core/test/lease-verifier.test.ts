import { describe, expect, it } from 'vitest';
import { KeyRing, b64urlEncode, generateEd25519, signJws } from '@trust/crypto';
import { LEASE_TYP, type LeaseClaims } from '@trust/shared-types';
import { SoftwareDeviceKey, verifyLease, type TrustBundle } from '../src/index.ts';

const T0 = new Date('2026-03-01T00:00:00Z');
const at = (s: number) => new Date(T0.getTime() + s * 1000);
const DAY = 86400;

const device = SoftwareDeviceKey.generate();
const INST = 'inst_0123456789abcdef0123';

function setup() {
  const ring = new KeyRing();
  const k = ring.generate('license');
  ring.activate(k.kid);
  const trust: TrustBundle = ring.trustBundle('license');
  const iat = Math.floor(T0.getTime() / 1000);
  const claims: LeaseClaims = {
    v: 1,
    jti: 'lse_1',
    iss: 'trust-platform',
    aud: 'product:pdf-pro',
    lic: 'lic_1',
    org: 'org_1',
    prd: 'prd_1',
    pln: 'pln_1',
    plv: 1,
    act: 'act_1',
    inst: INST,
    dev: 'dev_1',
    cnf: { jkt: device.thumbprint },
    kind: 'subscription',
    tier: 'professional',
    ent: { pdf_editing: true },
    cap: ['OCR_ADVANCED'],
    dl: 3,
    iat,
    nbf: iat,
    refresh_after: iat + 15 * DAY,
    exp: iat + 30 * DAY,
  };
  const sign = (c: Record<string, unknown>, kid = k.kid) =>
    signJws(c, { typ: LEASE_TYP, kid }, ring.custody);
  const opts = (now: Date, extra: Record<string, unknown> = {}) => ({
    trust,
    productCode: 'pdf-pro',
    installationId: INST,
    deviceThumbprint: device.thumbprint,
    now,
    ...extra,
  });
  return { ring, k, trust, claims, sign, opts };
}

describe('verifyLease — authenticity and bindings', () => {
  it('accepts a genuine lease', async () => {
    const { claims, sign, opts } = setup();
    const r = verifyLease(await sign({ ...claims }), opts(at(DAY)));
    expect(r.state).toBe('valid');
  });

  it('rejects an edited payload (self-upgrade attempt)', async () => {
    const { claims, sign, opts } = setup();
    const [h, , s] = (await sign({ ...claims })).split('.') as [string, string, string];
    const forged = `${h}.${b64urlEncode(JSON.stringify({ ...claims, cap: ['OCR_ADVANCED', 'AI_DOCUMENT_ASSISTANT'], tier: 'enterprise' }))}.${s}`;
    expect(verifyLease(forged, opts(at(DAY)))).toEqual({
      state: 'invalid',
      reason: 'bad_signature',
    });
  });

  it('rejects leases signed by an unknown or attacker key', async () => {
    const { claims, opts } = setup();
    const evil = new KeyRing();
    const ek = evil.generate('license');
    evil.activate(ek.kid);
    const t = await signJws({ ...claims }, { typ: LEASE_TYP, kid: ek.kid }, evil.custody);
    expect(verifyLease(t, opts(at(DAY)))).toEqual({ state: 'invalid', reason: 'unknown_key' });
    // attacker re-uses a legit kid but signs with their own private key
    const { k } = setup();
    const impostor = new KeyRing();
    impostor.importPrivateKeyPem(
      'license',
      generateEd25519().privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      k.kid,
    );
    const t2 = await signJws({ ...claims }, { typ: LEASE_TYP, kid: k.kid }, impostor.custody);
    expect(t2.split('.')).toHaveLength(3); // really signed, so the rejection below is meaningful
    const s2 = setup();
    expect(
      verifyLease(t2, {
        ...s2.opts(at(DAY)),
        trust: { schema: 1, keys: [{ kid: k.kid, jwk: s2.k.publicJwk }] },
      }),
    ).toEqual({ state: 'invalid', reason: 'bad_signature' });
  });

  it.each([
    ['wrong_product', { productCode: 'other-product' }],
    ['wrong_installation', { installationId: 'inst_ffffffffffffffffffff' }],
    ['wrong_device', { deviceThumbprint: 'AAAA' }],
    ['wrong_issuer', { issuer: 'someone-else' }],
  ])('rejects a lease replayed onto the wrong %s', async (reason, extra) => {
    const { claims, sign, opts } = setup();
    expect(verifyLease(await sign({ ...claims }), opts(at(DAY), extra))).toEqual({
      state: 'invalid',
      reason,
    });
  });

  it('rejects malformed tokens and structurally invalid claims', async () => {
    const { claims, sign, opts } = setup();
    expect(verifyLease('not.a.jws', opts(at(0)))).toMatchObject({ state: 'invalid' });
    expect(verifyLease('', opts(at(0)))).toMatchObject({ state: 'invalid' });
    const { exp: _e, ...noExp } = claims;
    void _e;
    expect(verifyLease(await sign(noExp), opts(at(0)))).toEqual({
      state: 'invalid',
      reason: 'bad_claims',
    });
    expect(verifyLease(await sign({ ...claims, exp: claims.iat }), opts(at(0)))).toEqual({
      state: 'invalid',
      reason: 'bad_claims',
    });
    expect(verifyLease(await sign({ ...claims, v: 2 }), opts(at(0)))).toEqual({
      state: 'invalid',
      reason: 'bad_claims',
    });
  });

  it('a revoked signing key (removed from the bundle) invalidates its leases; a deprecated key still verifies', async () => {
    const { ring, k, claims, sign, opts } = setup();
    const token = await sign({ ...claims });
    ring.activate(ring.generate('license').kid); // rotate: k is now deprecated
    expect(verifyLease(token, opts(at(DAY), { trust: ring.trustBundle('license') })).state).toBe(
      'valid',
    );
    ring.revoke(k.kid, 'compromise');
    expect(verifyLease(token, opts(at(DAY), { trust: ring.trustBundle('license') }))).toEqual({
      state: 'invalid',
      reason: 'unknown_key',
    });
  });
});

describe('verifyLease — time', () => {
  it('valid → refresh_recommended at half-life → expired after exp (+skew)', async () => {
    const { claims, sign, opts } = setup();
    const t = await sign({ ...claims });
    expect(verifyLease(t, opts(at(14 * DAY))).state).toBe('valid');
    expect(verifyLease(t, opts(at(15 * DAY))).state).toBe('refresh_recommended');
    expect(verifyLease(t, opts(at(29 * DAY))).state).toBe('refresh_recommended');
    expect(verifyLease(t, opts(at(30 * DAY + 200))).state).toBe('refresh_recommended'); // within 5 min skew
    expect(verifyLease(t, opts(at(30 * DAY + 301))).state).toBe('expired');
  });

  it('tolerates reasonable skew at the start (clock slightly behind) but flags large future-dating', async () => {
    const { claims, sign, opts } = setup();
    const t = await sign({ ...claims });
    expect(verifyLease(t, opts(at(-120))).state).toBe('valid');
    expect(verifyLease(t, opts(at(-3 * 3600))).state).toBe('clock_anomaly');
  });

  it('detects clock rollback using the persisted high-water mark', async () => {
    const { claims, sign, opts } = setup();
    const t = await sign({ ...claims });
    const first = verifyLease(t, opts(at(20 * DAY)));
    if (first.state === 'invalid') throw new Error('unexpected');
    expect(first.nextLastSeenAt).toEqual(at(20 * DAY));
    // user rewinds clock to "extend" an expired lease
    const rolled = verifyLease(t, opts(at(10 * DAY), { lastSeenAt: first.nextLastSeenAt }));
    expect(rolled.state).toBe('clock_anomaly');
    // a small backwards jump (NTP correction) is tolerated and does not lower the high-water mark
    const small = verifyLease(t, opts(at(20 * DAY - 60), { lastSeenAt: first.nextLastSeenAt }));
    expect(small.state).toBe('refresh_recommended');
    if (small.state !== 'invalid') expect(small.nextLastSeenAt).toEqual(at(20 * DAY));
  });

  it('skew tolerance is clamped so it cannot be configured into a bypass', async () => {
    const { claims, sign, opts } = setup();
    const t = await sign({ ...claims });
    expect(
      verifyLease(t, opts(at(30 * DAY + 10 * DAY), { skewSeconds: 10 * DAY * 1000 })).state,
    ).toBe('expired');
  });

  it('expired leases still return the claims so the host can show a recoverable state (no data loss path)', async () => {
    const { claims, sign, opts } = setup();
    const r = verifyLease(await sign({ ...claims }), opts(at(60 * DAY)));
    expect(r.state).toBe('expired');
    if (r.state === 'expired') expect(r.claims.lic).toBe('lic_1');
  });
});
