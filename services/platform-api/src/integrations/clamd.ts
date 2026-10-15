import { connect } from 'node:net';
import { createHash } from 'node:crypto';
import type { FileScanner, ScanInput, ScanVerdict } from '@trust/sharing';

/**
 * ClamAV over the clamd INSTREAM protocol (operator-run daemon on a private network). A clean answer is the exact
 * `stream: OK`; anything unexpected is an error, which the job worker retries and finally treats as a rejection
 * (fail closed). clamd's StreamMaxLength must be at least the largest permitted file size.
 */
export class ClamdScanner implements FileScanner {
  readonly name = 'clamav';
  readonly #host: string;
  readonly #port: number;
  readonly #timeoutMs: number;

  constructor(opts: { host: string; port: number; timeoutMs?: number }) {
    this.#host = opts.host;
    this.#port = opts.port;
    this.#timeoutMs = opts.timeoutMs ?? 120_000;
  }

  async scan(input: ScanInput): Promise<ScanVerdict> {
    const hash = createHash('sha256');
    let size = 0;
    const socket = connect({ host: this.#host, port: this.#port });
    socket.setTimeout(this.#timeoutMs);
    const reply = new Promise<string>((resolve, reject) => {
      let buf = '';
      socket.on('data', (d) => {
        buf += d.toString('utf8');
        if (buf.length > 4096) socket.destroy(new Error('clamd reply too long'));
        if (buf.includes('\0')) resolve(buf.slice(0, buf.indexOf('\0')));
      });
      socket.on('timeout', () => socket.destroy(new Error('clamd timeout')));
      socket.on('error', reject);
      socket.on('close', () => reject(new Error('clamd closed the connection')));
    });
    reply.catch(() => undefined);
    const write = (b: Buffer) =>
      new Promise<void>((res, rej) => socket.write(b, (e) => (e ? rej(e) : res())));
    try {
      await new Promise<void>((res, rej) => {
        socket.once('connect', res);
        socket.once('error', rej);
      });
      await write(Buffer.from('zINSTREAM\0'));
      for await (const chunk of await input.open()) {
        const b = Buffer.from(chunk);
        hash.update(b);
        size += b.length;
        for (let off = 0; off < b.length; off += 65536) {
          const piece = b.subarray(off, off + 65536);
          const len = Buffer.alloc(4);
          len.writeUInt32BE(piece.length);
          await write(Buffer.concat([len, piece]));
        }
      }
      await write(Buffer.alloc(4));
      const answer = (await reply).trim();
      const sha256 = hash.digest('hex');
      if (answer === 'stream: OK') return { verdict: 'clean', reason: null, sha256, size };
      const found = /^stream: (.{1,200}) FOUND$/.exec(answer);
      if (found)
        return {
          verdict: 'rejected',
          reason: `malware:${found[1]!.replace(/[^\w.-]/g, '_').slice(0, 80)}`,
          sha256,
          size,
        };
      throw Object.assign(new Error('clamd error'), { code: 'CLAMD_ERROR' });
    } finally {
      socket.destroy();
    }
  }
}
