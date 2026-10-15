import { createHash } from 'node:crypto';
import { FILE_KINDS, magicMatches } from './policy.ts';
import type { FileScanner, ScanInput, ScanVerdict } from './storage.ts';

// The industry-standard antivirus test string. Detecting it proves the quarantine path end to end without
// handling real malware. Assembled from parts so this source file is not itself flagged by antivirus tools.
export const EICAR = Buffer.from(
  ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join(''),
  'latin1',
);

/**
 * Always-on structural checks: the bytes must match the permitted format named by the extension, and must not
 * contain the EICAR signature. It is NOT antivirus; production deployments chain a real engine (ClamAV,
 * `CLAMD_HOST`) after it. Computes the content digest recorded on the blob.
 */
export class BasicContentScanner implements FileScanner {
  readonly name = 'basic';
  async scan(input: ScanInput): Promise<ScanVerdict> {
    const kind = FILE_KINDS[input.ext];
    const hash = createHash('sha256');
    let size = 0;
    let head = Buffer.alloc(0);
    let tail = Buffer.alloc(0);
    let eicar = false;
    for await (const chunk of await input.open()) {
      const buf = Buffer.from(chunk);
      hash.update(buf);
      size += buf.length;
      if (head.length < 16384) head = Buffer.concat([head, buf.subarray(0, 16384 - head.length)]);
      const window = Buffer.concat([tail, buf]);
      if (window.includes(EICAR)) eicar = true;
      tail = window.subarray(Math.max(0, window.length - EICAR.length + 1));
    }
    const sha256 = hash.digest('hex');
    if (!kind) return { verdict: 'rejected', reason: 'type_not_permitted', sha256, size };
    if (eicar) return { verdict: 'rejected', reason: 'malware_signature', sha256, size };
    if (size === 0) return { verdict: 'rejected', reason: 'empty', sha256, size };
    if (!magicMatches(kind, head))
      return { verdict: 'rejected', reason: 'content_does_not_match_type', sha256, size };
    return { verdict: 'clean', reason: null, sha256, size };
  }
}

/** Runs scanners in order; the first rejection wins. The digest and size come from the first scanner. */
export class ChainedScanner implements FileScanner {
  readonly name: string;
  readonly #scanners: FileScanner[];
  constructor(scanners: FileScanner[]) {
    if (!scanners.length) throw new Error('at least one scanner is required');
    this.#scanners = scanners;
    this.name = scanners.map((s) => s.name).join('+');
  }
  async scan(input: ScanInput): Promise<ScanVerdict> {
    const first = await this.#scanners[0]!.scan(input);
    if (first.verdict === 'rejected') return first;
    for (const s of this.#scanners.slice(1)) {
      const v = await s.scan(input);
      if (v.verdict === 'rejected') return { ...first, verdict: 'rejected', reason: v.reason };
    }
    return first;
  }
}
