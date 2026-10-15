import { describe, expect, it } from 'vitest';
import { BasicContentScanner, ChainedScanner, EICAR, type FileScanner } from '../src/index.ts';

const chunks = (...parts: Array<string | Buffer>) => ({
  open: async () =>
    (async function* () {
      for (const p of parts) yield Buffer.isBuffer(p) ? p : Buffer.from(p, 'latin1');
    })(),
});
const scanner = new BasicContentScanner();

describe('quarantine content checks', () => {
  it('accepts content that matches its permitted type and records digest and size', async () => {
    const v = await scanner.scan({ ext: 'pdf', ...chunks('%PDF-1.7\n', 'rest') });
    expect(v).toMatchObject({ verdict: 'clean', size: 13 });
    expect(v.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect((await scanner.scan({ ext: 'txt', ...chunks('hello') })).verdict).toBe('clean');
    expect(
      (await scanner.scan({ ext: 'docx', ...chunks(Buffer.from('504b030414', 'hex')) })).verdict,
    ).toBe('clean');
  });

  it('rejects disguised, empty, unknown and malware-signature content', async () => {
    expect((await scanner.scan({ ext: 'pdf', ...chunks('MZ\x90\x00 not a pdf') })).reason).toBe(
      'content_does_not_match_type',
    );
    expect((await scanner.scan({ ext: 'txt', ...chunks('bin\x00ary') })).reason).toBe(
      'content_does_not_match_type',
    );
    expect((await scanner.scan({ ext: 'pdf', ...chunks() })).reason).toBe('empty');
    expect((await scanner.scan({ ext: 'exe', ...chunks('MZ') })).reason).toBe('type_not_permitted');
    // The signature split across chunk boundaries is still found.
    const half = Math.floor(EICAR.length / 2);
    const v = await scanner.scan({
      ext: 'txt',
      ...chunks('prefix ', EICAR.subarray(0, half), EICAR.subarray(half), ' suffix'),
    });
    expect(v).toMatchObject({ verdict: 'rejected', reason: 'malware_signature' });
  });

  it('chains scanners: any rejection rejects', async () => {
    const reject: FileScanner = {
      name: 'av',
      scan: async () => ({ verdict: 'rejected', reason: 'av:Found', sha256: '', size: 0 }),
    };
    const chained = new ChainedScanner([scanner, reject]);
    expect(chained.name).toBe('basic+av');
    expect(await chained.scan({ ext: 'pdf', ...chunks('%PDF-') })).toMatchObject({
      verdict: 'rejected',
      reason: 'av:Found',
      size: 5,
    });
  });
});
