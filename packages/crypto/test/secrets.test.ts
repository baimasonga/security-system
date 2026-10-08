import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  generateLicenseKey,
  licenseKeyDigest,
  newId,
  normalizeLicenseKey,
} from '../src/index.ts';

describe('license keys and ids', () => {
  it('generates well-formed, unique, high-entropy keys', () => {
    const keys = new Set(Array.from({ length: 500 }, generateLicenseKey));
    expect(keys.size).toBe(500);
    for (const k of keys)
      expect(k).toMatch(
        /^LK-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/,
      );
  });
  it('digest is pepper-bound and tolerant of case and ambiguous characters', () => {
    const k = generateLicenseKey();
    expect(licenseKeyDigest('pepper-a', k)).toBe(licenseKeyDigest('pepper-a', k.toLowerCase()));
    expect(licenseKeyDigest('pepper-a', k)).not.toBe(licenseKeyDigest('pepper-b', k));
    expect(normalizeLicenseKey(' lk-oi1l ')).toBe('LK-0111');
    expect(licenseKeyDigest('p', k)).not.toContain(k);
  });
  it('ids are prefixed and unique; constantTimeEqual handles length mismatch', () => {
    expect(newId('lic')).toMatch(/^lic_[0-9a-f]{24}$/);
    expect(newId('lic')).not.toBe(newId('lic'));
    expect(constantTimeEqual('a', 'a')).toBe(true);
    expect(constantTimeEqual('a', 'ab')).toBe(false);
  });
});
