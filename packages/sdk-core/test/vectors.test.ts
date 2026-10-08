import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyLease } from '../src/index.ts';

// The committed vectors are the cross-language contract: other SDKs must reproduce these results.
const file = fileURLToPath(new URL('../../../docs/api/lease-test-vectors.json', import.meta.url));
const v = JSON.parse(readFileSync(file, 'utf8')) as {
  trust_bundle: Parameters<typeof verifyLease>[1]['trust'];
  context: {
    product_code: string;
    installation_id: string;
    device_thumbprint: string;
    issuer: string;
    skew_seconds: number;
  };
  cases: Array<{
    name: string;
    token: string;
    now: string;
    last_seen_at?: string;
    context?: Partial<{ product_code: string; installation_id: string; device_thumbprint: string }>;
    expect: { state: string; reason?: string };
  }>;
};

describe('lease test vectors (docs/api/lease-test-vectors.json)', () => {
  it('has meaningful coverage', () => {
    expect(v.cases.length).toBeGreaterThanOrEqual(12);
    expect(new Set(v.cases.map((c) => c.expect.state))).toEqual(
      new Set(['valid', 'refresh_recommended', 'expired', 'clock_anomaly', 'invalid']),
    );
    expect(JSON.stringify(v)).not.toMatch(/PRIVATE|"d"\s*:/);
  });
  it.each(v.cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const ctx = { ...v.context, ...c.context };
    const r = verifyLease(c.token, {
      trust: v.trust_bundle,
      productCode: ctx.product_code,
      installationId: ctx.installation_id,
      deviceThumbprint: ctx.device_thumbprint,
      issuer: v.context.issuer,
      skewSeconds: v.context.skew_seconds,
      now: new Date(c.now),
      lastSeenAt: c.last_seen_at ? new Date(c.last_seen_at) : undefined,
    });
    expect(r.state).toBe(c.expect.state);
    if (c.expect.reason) expect(r).toMatchObject({ reason: c.expect.reason });
  });
});
