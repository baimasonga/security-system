import { describe, expect, it } from 'vitest';
import { SharingKeys, newPublicCode, newSubmissionSecret, tokenHash } from '../src/index.ts';

const keys = new SharingKeys('k'.repeat(40));

describe('sharing tokens and grants', () => {
  it('derives stable, unpredictable, purpose-separated link tokens', () => {
    const t = keys.token('share', 'lnk_1', 'salt');
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(keys.token('share', 'lnk_1', 'salt')).toBe(t);
    expect(keys.token('request', 'lnk_1', 'salt')).not.toBe(t);
    expect(keys.token('share', 'lnk_1', 'salt2')).not.toBe(t);
    expect(new SharingKeys('j'.repeat(40)).token('share', 'lnk_1', 'salt')).not.toBe(t);
    expect(keys.token('short', 'sln_1', 's', 16)).toHaveLength(16);
    expect(tokenHash(t)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('refuses a short server secret', () => {
    expect(() => new SharingKeys('short')).toThrow();
  });

  it('accepts only untampered, unexpired grants', () => {
    const now = Date.parse('2026-03-01T00:00:00Z');
    const g = keys.grant({ k: 'share', s: 'lnk_1', u: null, exp: now / 1000 + 60 });
    expect(keys.verifyGrant(g, now)).toMatchObject({ s: 'lnk_1' });
    expect(keys.verifyGrant(g, now + 61_000)).toBeUndefined();
    const [, body, sig] = g.split('.');
    const forged = Buffer.from(
      JSON.stringify({ k: 'share', s: 'lnk_2', u: null, exp: now / 1000 + 60 }),
    ).toString('base64url');
    expect(keys.verifyGrant(`g1.${forged}.${sig}`, now)).toBeUndefined();
    expect(keys.verifyGrant(`g1.${body}.${'A'.repeat(43)}`, now)).toBeUndefined();
    expect(new SharingKeys('j'.repeat(40)).verifyGrant(g, now)).toBeUndefined();
    expect(keys.verifyGrant(undefined, now)).toBeUndefined();
    expect(keys.verifyGrant('x'.repeat(2000), now)).toBeUndefined();
  });

  it('generates readable public codes and high-entropy submission secrets', () => {
    expect(newPublicCode()).toMatch(/^[a-hj-km-np-z2-9]{8}$/);
    expect(newSubmissionSecret()).toMatch(/^sub_[A-Za-z0-9_-]{43}$/);
  });
});
