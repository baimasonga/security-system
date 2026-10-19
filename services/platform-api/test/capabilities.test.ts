import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareDeviceKey, verifyCapabilityToken, type TrustBundle } from '@trust/sdk-core';
import { buildProofMessage, type ProofPurpose } from '@trust/crypto/verify';
import { generateEd25519, kidForPublicKey, signJws, SoftwareKeyCustody } from '@trust/crypto';
import { CAPABILITY_TYP } from '@trust/shared-types';
import { defaultLicensingConfig } from '@trust/licensing';
import { makeEnv, type Env } from './harness.ts';

let env: Env;
afterEach(async () => env?.app.close());

const INST = 'inst_capabilitytestcapab01';

async function setup() {
  env = await makeEnv();
  const u = await env.register('cap-user@example.test');
  const lic = await env.provision(u.orgId); // plan capabilities: OCR_ADVANCED, CLOUD_SYNC
  const dev = SoftwareDeviceKey.generate();
  const ch = await env.call('POST', '/v1/devices/challenges', {
    body: { purpose: 'activate', installation_id: INST },
  });
  const act = await env.call('POST', '/v1/licenses/activate', {
    token: u.token,
    body: {
      license_key: lic.licenseKey,
      installation_id: INST,
      device_public_key: dev.publicJwk,
      nonce: ch.body.nonce,
      signature: dev.sign(
        buildProofMessage({
          purpose: 'activate',
          nonce: ch.body.nonce,
          installationId: INST,
          subjectId: '',
          thumbprint: dev.thumbprint,
        }),
      ),
    },
  });
  expect(act.status).toBe(200);
  const activationId = act.body.activation_id as string;
  const proof = async (purpose: ProofPurpose, signAs: ProofPurpose = purpose) => {
    const c = await env.call('POST', '/v1/devices/challenges', {
      body: { purpose, installation_id: INST, subject_id: activationId },
    });
    return {
      activation_id: activationId,
      installation_id: INST,
      nonce: c.body.nonce as string,
      signature: dev.sign(
        buildProofMessage({
          purpose: signAs,
          nonce: c.body.nonce,
          installationId: INST,
          subjectId: activationId,
          thumbprint: dev.thumbprint,
        }),
      ),
    };
  };
  const request = async (
    capability: string,
    service = 'ocr',
    p?: Awaited<ReturnType<typeof proof>>,
  ) =>
    env.call('POST', '/v1/capabilities/token', {
      body: { ...(p ?? (await proof('capability'))), capability, service },
    });
  const trust = (await env.call('GET', '/v1/keys/trust-bundle')).body as TrustBundle;
  return { u, lic, dev, activationId, proof, request, trust, lease: act.body.lease as string };
}

const actions = async () => (await env.c.audit.list({ limit: 500 })).map((e) => e.action);

describe('capability tokens', () => {
  it('issues a short-lived, device-bound token for a capability the license grants', async () => {
    const { request, trust, dev, activationId } = await setup();
    const r = await request('OCR_ADVANCED');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ capability: 'OCR_ADVANCED', audience: 'svc:ocr' });
    const check = verifyCapabilityToken(r.body.token, {
      trust,
      service: 'ocr',
      capability: 'OCR_ADVANCED',
      deviceThumbprint: dev.thumbprint,
      now: env.clock.now(),
    });
    expect(check.ok).toBe(true);
    if (!check.ok) return;
    expect(check.claims.sub).toBe(activationId);
    expect(check.claims.exp - check.claims.iat).toBe(300);
    expect(await actions()).toContain('capability.issued');
  });

  it('never grants a capability the resolved plan does not contain', async () => {
    const { request } = await setup();
    const r = await request('UNLIMITED_EVERYTHING');
    expect(r.status).toBe(403);
    expect(r.body.code).toBe('forbidden');
    expect(await actions()).toContain('capability.denied');
    expect((await request('ocr_advanced')).status).toBe(400); // malformed capability name
    expect((await request('OCR_ADVANCED', 'Bad Service')).status).toBe(400);
  });

  it('requires a fresh device proof for the capability purpose', async () => {
    const { request, proof } = await setup();
    // a refresh challenge, or a proof signed for another purpose, does not work
    expect((await request('OCR_ADVANCED', 'ocr', await proof('refresh'))).status).toBe(403);
    expect(
      (await request('OCR_ADVANCED', 'ocr', await proof('capability', 'refresh'))).status,
    ).toBe(403);
    const p = await proof('capability');
    expect((await request('OCR_ADVANCED', 'ocr', p)).status).toBe(200);
    expect((await request('OCR_ADVANCED', 'ocr', p)).status).toBe(403); // replayed nonce
  });

  it('refuses unknown challenge purposes in the service itself (defense in depth behind the schema)', async () => {
    await setup();
    await expect(
      env.c.licensing.issueChallenge({ purpose: 'bogus' as never, installationId: INST }),
    ).rejects.toThrow(/invalid purpose/);
  });

  it('stops issuing as soon as the license is revoked or suspended', async () => {
    const { request, u, lic } = await setup();
    const op = await env.operatorToken();
    await env.call('POST', `/v1/admin/organizations/${u.orgId}/licenses/${lic.licenseId}/suspend`, {
      token: op,
      body: { reason: 'payment dispute' },
    });
    const r = await request('OCR_ADVANCED');
    expect(r.status).toBe(403);
    expect(r.body.code).toBe('license_suspended');
  });
});

describe('verifyCapabilityToken (service side)', () => {
  it('rejects leases, other services, other capabilities, other devices, tampering and expiry', async () => {
    const { request, trust, dev, lease } = await setup();
    const token = (await request('OCR_ADVANCED')).body.token as string;
    const now = env.clock.now();
    const base = { trust, service: 'ocr', capability: 'OCR_ADVANCED', now };
    const reason = (t: string, o = {}) => {
      const r = verifyCapabilityToken(t, { ...base, ...o });
      return r.ok ? 'ok' : r.reason;
    };
    expect(reason(token)).toBe('ok');
    expect(reason(lease)).toBe('malformed'); // explicit typing: a lease is not a capability token
    expect(reason(token, { service: 'convert' })).toBe('wrong_audience');
    expect(reason(token, { capability: 'CLOUD_SYNC' })).toBe('wrong_capability');
    expect(reason(token, { deviceThumbprint: SoftwareDeviceKey.generate().thumbprint })).toBe(
      'wrong_device',
    );
    expect(reason(token, { deviceThumbprint: dev.thumbprint })).toBe('ok');
    const [h, p, s] = token.split('.');
    expect(reason(`${h}.${p}.${s!.slice(0, 10)}${s![10] === 'A' ? 'B' : 'A'}${s!.slice(11)}`)).toBe(
      'bad_signature',
    );
    expect(reason(token, { trust: { schema: 1, keys: [] } })).toBe('unknown_key');
    expect(reason(token, { now: new Date(now.getTime() + 361_000) })).toBe('expired');
    expect(reason(token, { now: new Date(now.getTime() + 359_000) })).toBe('ok');
    expect(reason(token, { now: new Date(now.getTime() - 61_000) })).toBe('not_yet_valid');
    expect(reason(token, { issuer: 'someone-else' })).toBe('wrong_issuer');
  });

  it('refuses a validly signed token whose lifetime exceeds 15 minutes', async () => {
    const { publicJwk, privateKey } = generateEd25519();
    const kid = kidForPublicKey(publicJwk);
    const custody = new SoftwareKeyCustody();
    custody.add(kid, privateKey);
    const iat = 1_800_000_000;
    const claims = {
      v: 1,
      jti: 'cap_x',
      iss: 'trust-platform',
      aud: 'svc:ocr',
      sub: 'act_x',
      org: 'org_x',
      lic: 'lic_x',
      prd: 'pdf-pro',
      cap: 'OCR_ADVANCED',
      cnf: { jkt: 'x' },
      iat,
      nbf: iat,
      exp: iat + 901,
    };
    const t = await signJws(claims, { typ: CAPABILITY_TYP, kid }, custody);
    const r = verifyCapabilityToken(t, {
      trust: { schema: 1, keys: [{ kid, jwk: publicJwk }] },
      service: 'ocr',
      capability: 'OCR_ADVANCED',
      now: new Date(iat * 1000),
    });
    expect(r).toEqual({ ok: false, reason: 'lifetime_too_long' });
  });

  it('bounds the configured token lifetime', () => {
    const pepper = 'p'.repeat(40);
    expect(defaultLicensingConfig({ licenseKeyPepper: pepper }).capabilityTtlSeconds).toBe(300);
    expect(() =>
      defaultLicensingConfig({ licenseKeyPepper: pepper, capabilityTtlSeconds: 10 }),
    ).toThrow();
    expect(() =>
      defaultLicensingConfig({ licenseKeyPepper: pepper, capabilityTtlSeconds: 901 }),
    ).toThrow();
  });
});
