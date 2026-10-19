import { describe, expect, it } from 'vitest';
import { checkClientEvent, contentViolation, sanitizeAttributes } from '../src/index.ts';

const rule = (name: string, attrs: Record<string, unknown>) => {
  const r = checkClientEvent(name, attrs);
  return r.ok ? 'ok' : r.violations.map((v) => `${v.field}:${v.rule}`).join(',');
};

describe('privacy firewall', () => {
  it('accepts allow-listed events with well-formed values', () => {
    expect(rule('app.started', { app_version: '3.2.1-beta+7', platform: 'windows' })).toBe('ok');
    expect(rule('feature.used', { feature: 'export.pdf', duration_ms: 1200 })).toBe('ok');
    expect(rule('app.error', { code: 'save_failed', component: 'editor' })).toBe('ok');
    expect(rule('app.started', {})).toBe('ok');
  });

  it('refuses unknown events, unknown fields, wrong types and out-of-range numbers', () => {
    expect(rule('document.contents', { text: 'hello' })).toBe('name:unknown_event');
    expect(rule('__proto__', {})).toBe('name:unknown_event');
    expect(rule('feature.used', { feature: 'x', user_email: 'a' })).toBe(
      'user_email:unknown_attribute',
    );
    expect(rule('feature.used', { duration_ms: '12' })).toBe('duration_ms:type');
    expect(rule('feature.used', { duration_ms: -1 })).toBe('duration_ms:type');
    expect(rule('app.started', { platform: 'beos' })).toBe('platform:pattern');
    expect(rule('feature.used', { feature: 'x'.repeat(49) })).toBe('feature:too_long');
    expect(rule('feature.used', { feature: 'Export PDF' })).toBe('feature:pattern');
  });

  it('detects personal data, secrets, locations and key material in any string', () => {
    const cases: Array<[string, string]> = [
      ['kamara@example.sl', 'looks_like_email'],
      ['https://intranet.example/doc', 'looks_like_url'],
      ['www.example.com', 'looks_like_url'],
      ['C:\\Users\\Aminata\\Documents', 'looks_like_path'],
      ['/home/aminata/contract.pdf', 'looks_like_path'],
      ['~/notes', 'looks_like_path'],
      ['+232 76 123 456', 'looks_like_phone'],
      ['4111 1111 1111 1111', 'looks_like_card'],
      ['eyJhbGciOiJFZERTQSJ9.e30', 'looks_like_secret'],
      ['sk_live_9fA2kLm3nP4qR5', 'looks_like_secret'],
      ['sess_Q2hhbmdlTWUxMjM0NTY3ODkwYWJj', 'looks_like_secret'],
      [`-----BEGIN ${'PRIVATE'} KEY-----`, 'looks_like_key_material'], // built at runtime: no key-like literal in the repo
      ['ssh-ed25519 AAAAC3', 'looks_like_key_material'],
    ];
    for (const [value, expected] of cases) expect(contentViolation(value), value).toBe(expected);
    for (const ok of ['3.2.1', 'export.pdf', 'save_failed', 'windows', 'v2', 'build-2026.10.19'])
      expect(contentViolation(ok), ok).toBeUndefined();
    // inside an otherwise allowed field the detector wins
    expect(rule('app.error', { code: 'kamara@example.sl' })).toBe('code:looks_like_email');
  });

  it('also scrubs server-side telemetry string attributes', () => {
    expect(sanitizeAttributes('activation.rejected', { reason: 'not_authorized' })).toEqual({
      reason: 'not_authorized',
    });
    expect(sanitizeAttributes('activation.rejected', { reason: 'user kamara@example.sl' })).toEqual(
      {},
    );
  });

  it('runs in bounded time on hostile input', () => {
    const hostile = ['a'.repeat(5000) + '@', '@'.repeat(5000), '/'.repeat(5000), '1 '.repeat(3000)];
    const t0 = performance.now();
    for (const h of hostile) {
      checkClientEvent('feature.used', { feature: h });
      contentViolation(h.slice(0, 256));
    }
    expect(performance.now() - t0).toBeLessThan(200);
  });
});
