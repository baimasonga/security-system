// Generates docs/api/lease-test-vectors.json — the executable cross-language contract for ADR-002.
// Contains ONLY public material (trust bundle, thumbprint) and signed tokens. The one-off signing
// key is discarded after generation. Run: node tools/gen-lease-vectors.ts > docs/api/lease-test-vectors.json
import { KeyRing, b64urlEncode, signJws } from '@trust/crypto';
import { LEASE_TYP, type LeaseClaims } from '@trust/shared-types';
import { SoftwareDeviceKey } from '@trust/sdk-core';

const T0 = Date.parse('2026-03-01T00:00:00Z') / 1000;
const DAY = 86400;
const iso = (s: number) => new Date(s * 1000).toISOString();

const ring = new KeyRing();
const key = ring.generate('license');
ring.activate(key.kid);
const device = SoftwareDeviceKey.generate();
const installationId = 'inst_vectorvectorvector01';

const claims: LeaseClaims = {
  v: 1,
  jti: 'lse_00000000000000000000vec1',
  iss: 'trust-platform',
  aud: 'product:pdf-pro',
  lic: 'lic_000000000000000000000001',
  org: 'org_000000000000000000000001',
  prd: 'prd_000000000000000000000001',
  pln: 'pln_000000000000000000000001',
  plv: 1,
  act: 'act_000000000000000000000001',
  inst: installationId,
  dev: 'dev_000000000000000000000001',
  cnf: { jkt: device.thumbprint },
  kind: 'subscription',
  tier: 'professional',
  ent: { ocr_pages_monthly: 5000, pdf_editing: true },
  cap: ['CLOUD_SYNC', 'OCR_ADVANCED'],
  dl: 3,
  iat: T0,
  nbf: T0,
  refresh_after: T0 + 15 * DAY,
  exp: T0 + 30 * DAY,
};
const sign = (c: object, k = key.kid, r = ring) =>
  signJws(c as Record<string, unknown>, { typ: LEASE_TYP, kid: k }, r.custody);
const token = await sign(claims);
const [h, p, s] = token.split('.') as [string, string, string];

const evil = new KeyRing();
const ek = evil.generate('license');
evil.activate(ek.kid);

const cases = [
  { name: 'valid early in life', token, now: iso(T0 + DAY), expect: { state: 'valid' } },
  {
    name: 'refresh recommended at half-life',
    token,
    now: iso(T0 + 15 * DAY),
    expect: { state: 'refresh_recommended' },
  },
  {
    name: 'tolerated within skew after exp',
    token,
    now: iso(T0 + 30 * DAY + 200),
    expect: { state: 'refresh_recommended' },
  },
  {
    name: 'expired beyond exp + skew',
    token,
    now: iso(T0 + 30 * DAY + 301),
    expect: { state: 'expired' },
  },
  {
    name: 'clock far behind issue time',
    token,
    now: iso(T0 - 3 * 3600),
    expect: { state: 'clock_anomaly' },
  },
  {
    name: 'clock rolled back vs high-water mark',
    token,
    now: iso(T0 + 10 * DAY),
    last_seen_at: iso(T0 + 20 * DAY),
    expect: { state: 'clock_anomaly' },
  },
  {
    name: 'payload edited (capability added)',
    token: `${h}.${b64urlEncode(JSON.stringify({ ...claims, cap: [...claims.cap, 'AI_DOCUMENT_ASSISTANT'] }))}.${s}`,
    now: iso(T0 + DAY),
    expect: { state: 'invalid', reason: 'bad_signature' },
  },
  {
    name: 'alg none',
    token: `${b64urlEncode(JSON.stringify({ alg: 'none', typ: LEASE_TYP, kid: key.kid }))}.${p}.`,
    now: iso(T0 + DAY),
    expect: { state: 'invalid', reason: 'malformed' },
  },
  {
    name: 'signed by unknown key',
    token: await sign(claims, ek.kid, evil),
    now: iso(T0 + DAY),
    expect: { state: 'invalid', reason: 'unknown_key' },
  },
  {
    name: 'wrong product',
    token,
    now: iso(T0 + DAY),
    context: { product_code: 'other-product' },
    expect: { state: 'invalid', reason: 'wrong_product' },
  },
  {
    name: 'wrong installation',
    token,
    now: iso(T0 + DAY),
    context: { installation_id: 'inst_someoneelsesinstall1' },
    expect: { state: 'invalid', reason: 'wrong_installation' },
  },
  {
    name: 'wrong device key',
    token,
    now: iso(T0 + DAY),
    context: { device_thumbprint: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    expect: { state: 'invalid', reason: 'wrong_device' },
  },
  {
    name: 'truncated signature',
    token: token.slice(0, token.length - 10),
    now: iso(T0 + DAY),
    expect: { state: 'invalid', reason: 'bad_signature' },
  },
  {
    name: 'missing signature segment',
    token: `${h}.${p}`,
    now: iso(T0 + DAY),
    expect: { state: 'invalid', reason: 'malformed' },
  },
];

console.log(
  JSON.stringify(
    {
      description:
        'Cross-language contract for offline leases (docs/adr/ADR-002). A conforming verifier must produce exactly `expect` for every case. skew_seconds defaults to 300.',
      trust_bundle: ring.trustBundle('license'),
      context: {
        product_code: 'pdf-pro',
        installation_id: installationId,
        device_thumbprint: device.thumbprint,
        issuer: 'trust-platform',
        skew_seconds: 300,
      },
      claims,
      cases,
    },
    null,
    2,
  ),
);
