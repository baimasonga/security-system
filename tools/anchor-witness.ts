// REFERENCE witness for audit anchors (ADR-010) — for development, demos and tests.
//
//   WITNESS_TOKEN=… WITNESS_FILE=./witness.jsonl [PORT=8099] node tools/anchor-witness.ts
//
// Appends every received manifest to a JSON Lines file, hash-chained to the previous entry, and returns the
// entry as a receipt. In production the witness must be a system the platform operator (and a database
// superuser) cannot rewrite: object storage with retention lock / WORM, a transparency log, a separate
// account's append-only store. A file on the same host is NOT that.
import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { manifestProblem, type AnchorManifest } from '@trust/audit';
import { canonicalJson, sha256Hex } from '@trust/crypto';

const token = process.env['WITNESS_TOKEN'] ?? '';
const file = process.env['WITNESS_FILE'] ?? './witness.jsonl';
if (token.length < 16) {
  console.error('WITNESS_TOKEN (>= 16 chars) is required');
  process.exit(2);
}

interface Entry {
  n: number;
  received_at: string;
  prev: string;
  hash: string;
  manifest: AnchorManifest;
}
let last: Entry | undefined;
if (existsSync(file)) {
  const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
  if (lines.length) last = JSON.parse(lines[lines.length - 1]!) as Entry;
}

const sameToken = (header: string | undefined) => {
  const a = Buffer.from(header ?? '');
  const b = Buffer.from(`Bearer ${token}`);
  return a.length === b.length && timingSafeEqual(a, b);
};

http
  .createServer((req, res) => {
    const reply = (code: number, body: string, receipt?: string) => {
      res.writeHead(code, {
        'content-type': 'text/plain',
        ...(receipt ? { 'x-witness-receipt': receipt } : {}),
      });
      res.end(body);
    };
    if (req.method !== 'POST') return reply(405, 'POST only');
    if (!sameToken(req.headers.authorization)) return reply(401, 'unauthorized');
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > 8_000_000) req.destroy();
      else chunks.push(c);
    });
    req.on('end', () => {
      let m: AnchorManifest;
      try {
        m = JSON.parse(Buffer.concat(chunks).toString('utf8')) as AnchorManifest;
      } catch {
        return reply(400, 'invalid json');
      }
      const bad = manifestProblem(m);
      if (bad) return reply(400, bad);
      if (last && last.manifest.anchor === m.anchor)
        return reply(200, 'already witnessed', `${last.n}:${last.hash.slice(0, 32)}`);
      const prev = last?.hash ?? '0'.repeat(64);
      const entry: Entry = {
        n: (last?.n ?? 0) + 1,
        received_at: new Date().toISOString(),
        prev,
        hash: '',
        manifest: m,
      };
      entry.hash = sha256Hex(prev + canonicalJson(m));
      const fd = openSync(file, 'a');
      try {
        appendFileSync(fd, JSON.stringify(entry) + '\n');
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      last = entry;
      reply(201, 'witnessed', `${entry.n}:${entry.hash.slice(0, 32)}`);
    });
  })
  .listen(Number(process.env['PORT'] ?? 8099), '127.0.0.1', () =>
    console.log(`witness listening; appending to ${file}`),
  );
