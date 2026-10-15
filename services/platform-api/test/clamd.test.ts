import { createServer, type Server } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { ClamdScanner } from '../src/integrations/clamd.ts';

let server: Server | undefined;
afterEach(() => server?.close());

/** Minimal clamd INSTREAM fake: parses length-prefixed chunks and answers from `decide`. */
function fakeClamd(decide: (bytes: Buffer) => string): Promise<number> {
  server = createServer((socket) => {
    let buf = Buffer.alloc(0);
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (!buf.subarray(0, 10).equals(Buffer.from('zINSTREAM\0'))) return;
      let off = 10;
      const chunks: Buffer[] = [];
      while (off + 4 <= buf.length) {
        const len = buf.readUInt32BE(off);
        if (len === 0) return void socket.end(`${decide(Buffer.concat(chunks))}\0`);
        if (off + 4 + len > buf.length) return;
        chunks.push(buf.subarray(off + 4, off + 4 + len));
        off += 4 + len;
      }
    });
  });
  return new Promise((r) =>
    server!.listen(0, '127.0.0.1', () => r((server!.address() as { port: number }).port)),
  );
}
const input = (...parts: string[]) => ({
  ext: 'pdf',
  open: async () =>
    (async function* () {
      for (const p of parts) yield Buffer.from(p);
    })(),
});

describe('ClamAV INSTREAM scanner', () => {
  it('streams the object and maps OK / FOUND answers', async () => {
    const seen: string[] = [];
    const port = await fakeClamd(
      (b) => (
        seen.push(b.toString()),
        b.includes('virus') ? 'stream: Win.Test.EICAR_HDB-1 FOUND' : 'stream: OK'
      ),
    );
    const scanner = new ClamdScanner({ host: '127.0.0.1', port });
    expect(await scanner.scan(input('%PDF-', 'clean'))).toMatchObject({
      verdict: 'clean',
      size: 10,
    });
    expect(await scanner.scan(input('%PDF-', 'virus'))).toMatchObject({
      verdict: 'rejected',
      reason: 'malware:Win.Test.EICAR_HDB-1',
    });
    expect(seen).toEqual(['%PDF-clean', '%PDF-virus']);
  });
  it('treats any other answer or a dead daemon as an error (the worker then fails closed)', async () => {
    const port = await fakeClamd(() => 'INSTREAM size limit exceeded. ERROR');
    await expect(new ClamdScanner({ host: '127.0.0.1', port }).scan(input('x'))).rejects.toThrow(
      'clamd error',
    );
    server!.close();
    await expect(
      new ClamdScanner({ host: '127.0.0.1', port, timeoutMs: 500 }).scan(input('x')),
    ).rejects.toThrow();
  });
});
