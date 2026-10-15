import { describe, expect, it } from 'vitest';
import {
  FREE_LIMITS,
  contentDisposition,
  effectiveLinkState,
  looksAutomated,
  magicMatches,
  permits,
  planParts,
  referrerHost,
  requireFileKind,
  resolveLimits,
  sanitizeFileName,
  sanitizeFolderPath,
  validateAlias,
  validateExternalDestination,
  validateHostname,
  FILE_KINDS,
} from '../src/index.ts';

const policy = { reservedHosts: ['rokela.example'], blockedHosts: ['evil.test'] };

describe('commercial limits', () => {
  it('never falls below the free baseline and takes the most generous valid license', () => {
    expect(resolveLimits([])).toEqual(FREE_LIMITS);
    const l = resolveLimits([
      { share_storage_bytes: 10, share_persistent: false },
      {
        share_storage_bytes: 50 * 1024 ** 3,
        share_upload_requests: true,
        share_retention_days: 30,
      },
      { share_storage_bytes: '9e99', share_custom_domains: 'yes' },
    ]);
    expect(l.storageBytes).toBe(50 * 1024 ** 3);
    expect(l.uploadRequests).toBe(true);
    expect(l.customDomains).toBe(false);
    expect(l.persistent).toBe(false);
    expect(l.maxRetentionDays).toBe(30);
  });
  it('caps absurd plan values at a hard ceiling', () => {
    expect(resolveLimits([{ share_retention_days: 10_000_000 }]).maxRetentionDays).toBe(3650);
  });
});

describe('permitted formats and names', () => {
  it('derives types from the extension and refuses executables and active content', () => {
    expect(requireFileKind('Report.PDF').contentType).toBe('application/pdf');
    for (const bad of ['setup.exe', 'page.html', 'icon.svg', 'run.sh', 'macro.docm', 'noext'])
      expect(() => requireFileKind(bad), bad).toThrow('not permitted');
    expect(() => requireFileKind('photo.png', ['pdf'])).toThrow('not permitted');
  });
  it('checks magic bytes', () => {
    expect(magicMatches(FILE_KINDS.png!, Buffer.from('89504e470d0a1a0a00', 'hex'))).toBe(true);
    expect(magicMatches(FILE_KINDS.png!, Buffer.from('%PDF-'))).toBe(false);
    expect(magicMatches(FILE_KINDS.webp!, Buffer.from('RIFF\0\0\0\0WEBPVP8 '))).toBe(true);
    expect(magicMatches(FILE_KINDS.webp!, Buffer.from('RIFF\0\0\0\0WAVEfmt '))).toBe(false);
  });
  it('sanitizes names: no paths, control or bidi characters', () => {
    expect(sanitizeFileName('../../etc/passwd.txt')).toBe('passwd.txt');
    expect(sanitizeFileName('invoice\u202egpj.pdf')).toBe('invoicegpj.pdf');
    expect(sanitizeFileName('a"b<c>.pdf')).toBe('a_b_c_.pdf');
    expect(() => sanitizeFileName('...')).toThrow();
    expect(() => sanitizeFileName(`${'a'.repeat(250)}.pdf`)).toThrow();
    expect(sanitizeFolderPath('Contracts/2026//Signed')).toBe('Contracts/2026/Signed');
    expect(() => sanitizeFolderPath('a/../b')).toThrow();
    expect(() => sanitizeFolderPath('a/'.repeat(11))).toThrow();
  });
  it('builds an RFC 6266 disposition that cannot break out of the header', () => {
    expect(contentDisposition('attachment', 'Ŋa "x";.pdf')).toBe(
      `attachment; filename="_a _x__.pdf"; filename*=UTF-8''%C5%8Aa%20%22x%22%3B.pdf`,
    );
  });
});

describe('short-link destinations and aliases', () => {
  it('accepts only public http(s) destinations', () => {
    expect(validateExternalDestination('https://shop.example.com/sale?x=1', policy)).toBe(
      'https://shop.example.com/sale?x=1',
    );
    for (const bad of [
      'javascript:alert(1)',
      'data:text/html,hi',
      'file:///etc/passwd',
      'ftp://files.example.com/',
      'https://user:pw@example.com/',
      'http://127.0.0.1/',
      'http://[::1]/',
      'http://0x7f000001/',
      'http://localhost:8080/',
      'http://metadata.google.internal/',
      'http://printer.local/',
      'https://example.com:8443/',
      'https://rokela.example/l/loop',
      'https://sub.evil.test/',
      'https://intranet/',
      `https://example.com/${'a'.repeat(2100)}`,
    ])
      expect(() => validateExternalDestination(bad, policy), bad).toThrow(
        'destination not permitted',
      );
  });
  it('allows readable aliases and refuses reserved or malformed ones', () => {
    expect(validateAlias(' Spring-Sale ')).toBe('spring-sale');
    for (const bad of ['ab', 'login', 'admin', '-x-', 'a--b', 'ünï', 'a b', 'x'.repeat(65)])
      expect(() => validateAlias(bad), bad).toThrow();
  });
  it('validates custom hostnames', () => {
    expect(validateHostname('Go.Example.COM.')).toBe('go.example.com');
    for (const bad of ['localhost', 'example', 'a..b.com', '-a.com', 'nas.local', 'x.123'])
      expect(() => validateHostname(bad), bad).toThrow();
  });
});

describe('analytics hygiene and link state', () => {
  it('flags obvious automation and keeps only the referring host', () => {
    expect(looksAutomated('Mozilla/5.0 (compatible; Googlebot/2.1)')).toBe(true);
    expect(looksAutomated('Microsoft Office/16.0 (Windows NT 10.0)')).toBe(true);
    expect(looksAutomated(undefined)).toBe(true);
    expect(
      looksAutomated('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130 Safari/537.36'),
    ).toBe(false);
    expect(referrerHost('https://News.Example/path?secret=1#x')).toBe('news.example');
    expect(referrerHost('android-app://com.x')).toBe('');
    expect(referrerHost('not a url')).toBe('');
  });
  it('evaluates status, expiry and target availability in that order', () => {
    const now = new Date('2026-03-01T00:00:00Z');
    expect(effectiveLinkState({ status: 'revoked', expiresAt: null }, now, true)).toBe('revoked');
    expect(effectiveLinkState({ status: 'active', expiresAt: now }, now, true)).toBe('expired');
    expect(effectiveLinkState({ status: 'active', expiresAt: null }, now, false)).toBe(
      'unavailable',
    );
    expect(effectiveLinkState({ status: 'active', expiresAt: new Date(+now + 1) }, now, true)).toBe(
      'active',
    );
  });
  it('maps permissions to actions', () => {
    expect(permits('view', 'download')).toBe(false);
    expect(permits('download', 'download')).toBe(true);
    expect(permits('review', 'comment')).toBe(true);
    expect(permits('download', 'comment')).toBe(false);
  });
  it('plans multipart uploads within S3 limits', () => {
    expect(planParts(1)).toEqual({ partSize: 8 * 1024 ** 2, partCount: 1 });
    expect(planParts(20 * 1024 ** 2)).toEqual({ partSize: 8 * 1024 ** 2, partCount: 3 });
    const big = planParts(200 * 1024 ** 3);
    expect(big.partCount).toBeLessThanOrEqual(10_000);
    expect(planParts(10, 4, 4)).toEqual({ partSize: 4, partCount: 3 });
    expect(() => planParts(0)).toThrow();
  });
});
