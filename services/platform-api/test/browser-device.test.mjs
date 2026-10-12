import { describe, expect, it } from 'vitest';
import { generateEd25519, jwkThumbprint } from '@trust/crypto';
import { sign } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { checkOffline, proofMessage } from '../src/web/device.mjs';
import { buildProofMessage } from '@trust/crypto/verify';
const key = generateEd25519();
const jwk = key.publicJwk;
const now = Date.now();
const payload = {
  v: 1,
  jti: 'lease',
  iss: 'trust-platform',
  aud: 'product:pdf',
  lic: 'lic',
  org: 'org',
  prd: 'product',
  pln: 'plan',
  plv: 1,
  act: 'act',
  inst: 'install',
  dev: 'device',
  cnf: { jkt: jwkThumbprint(jwk) },
  kind: 'perpetual',
  tier: 'professional',
  ent: { editing: true },
  cap: ['EDIT'],
  dl: 3,
  iat: Math.floor(now / 1000),
  nbf: Math.floor(now / 1000),
  refresh_after: Math.floor(now / 1000) + 60,
  exp: Math.floor(now / 1000) + 120,
};
const options = {
  trust: { keys: [{ kid: 'test', jwk }] },
  product: 'pdf',
  installation: 'install',
  thumb: jwkThumbprint(jwk),
  now,
};
const lease = (over = {}) => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'EdDSA', typ: 'lease+jws', kid: 'test' }),
  ).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, ...over })).toString('base64url');
  const message = header + '.' + body;
  return message + '.' + sign(null, Buffer.from(message), key.privateKey).toString('base64url');
};
describe('browser device verification', () => {
  it('uses the server proof format', () => {
    const args = {
      purpose: 'refresh',
      nonce: 'nonce',
      installationId: 'install',
      subjectId: 'act',
      thumbprint: 'thumb',
    };
    expect(proofMessage('refresh', 'nonce', 'install', 'act', 'thumb')).toBe(
      buildProofMessage(args),
    );
  });
  it('verifies a real signed lease with WebCrypto', async () => {
    const result = await checkOffline(lease(), options);
    expect(result.state).toBe('valid');
    expect(result.entitlements.editing).toBe(true);
  });
  it.each([
    { aud: 'product:other' },
    { inst: 'other' },
    { cnf: { jkt: 'other' } },
    { iss: 'attacker' },
    { exp: 0 },
    { v: 2 },
  ])('rejects invalid signed bindings/claims %j', async (over) => {
    const result = await checkOffline(lease(over), options);
    expect(result.state).toBe('invalid');
    expect(result.entitlements).toEqual({});
  });
  it('rejects tampering and untrusted keys', async () => {
    const original = lease();
    const [header, body, encodedSignature] = original.split('.');
    const signature = Buffer.from(encodedSignature, 'base64url');
    signature[0] ^= 1; // Guaranteed byte change; a fixed suffix can equal the genuine random suffix.
    const tampered = `${header}.${body}.${signature.toString('base64url')}`;
    expect(tampered).not.toBe(original);
    expect((await checkOffline(tampered, options)).state).toBe('invalid');
    expect((await checkOffline(lease(), { ...options, trust: { keys: [] } })).state).toBe(
      'invalid',
    );
  });
  it('does not expose entitlements after expiry or clock rollback', async () => {
    expect((await checkOffline(lease(), { ...options, now: now + 1000000 })).entitlements).toEqual(
      {},
    );
    expect((await checkOffline(lease(), { ...options, lastSeen: now + 1000000 })).state).toBe(
      'clock_anomaly',
    );
  });
});
