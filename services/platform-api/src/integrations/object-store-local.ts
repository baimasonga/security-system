import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { once } from 'node:events';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import Fastify, { type FastifyInstance } from 'fastify';
import { constantTimeEqual } from '@trust/crypto';
import {
  contentDisposition,
  type ObjectStore,
  type SignedDownload,
  type UploadedPart,
} from '@trust/sharing';

// Local object storage with S3-style signed URLs, for development, tests and single-host deployments outside
// production. Files live under one operator-chosen directory; every on-disk name is a digest or a random id, never
// tenant-chosen text. The companion content server (below) is a SEPARATE origin and listener: it serves bytes only
// for valid, unexpired signatures and never sees sessions or cookies.

const MAX_PART = 5 * 1024 ** 3;

export class LocalObjectStore implements ObjectStore {
  readonly kind = 'local';
  readonly minPartBytes: number;
  readonly #root: string;
  readonly #key: Buffer;
  readonly #origin: string;

  constructor(opts: {
    root: string;
    signingSecret: string;
    contentOrigin: string;
    minPartBytes?: number;
  }) {
    this.#root = opts.root;
    this.#key = createHmac('sha256', opts.signingSecret)
      .update('rokela-sharing:local-content:v1')
      .digest();
    this.#origin = opts.contentOrigin.replace(/\/$/, '');
    this.minPartBytes = opts.minPartBytes ?? 5 * 1024 * 1024;
  }

  get contentOrigin(): string {
    return this.#origin;
  }

  #obj(key: string) {
    return join(this.#root, 'objects', createHash('sha256').update(key).digest('hex'));
  }
  #mp(uploadId: string) {
    if (!/^[0-9a-f]{32}$/.test(uploadId)) throw new Error('invalid upload id');
    return join(this.#root, 'multipart', uploadId);
  }

  sign(params: Record<string, string>): string {
    const canonical = Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join('&');
    return createHmac('sha256', this.#key).update(canonical).digest('base64url');
  }
  /** Returns the verified parameters, or undefined for a bad or expired signature. */
  verify(query: Record<string, unknown>, nowMs: number): Record<string, string> | undefined {
    const params: Record<string, string> = {};
    for (const [k, v] of Object.entries(query))
      if (typeof v === 'string' && k !== 's') params[k] = v;
    const sig = typeof query['s'] === 'string' ? query['s'] : '';
    if (!sig || !constantTimeEqual(this.sign(params), sig)) return undefined;
    if (!/^\d+$/.test(params['e'] ?? '') || Number(params['e']) * 1000 <= nowMs) return undefined;
    return params;
  }
  #url(path: string, params: Record<string, string>) {
    return `${this.#origin}${path}?${new URLSearchParams({ ...params, s: this.sign(params) }).toString()}`;
  }

  async createMultipart(key: string, contentType: string) {
    const uploadId = randomBytes(16).toString('hex');
    await mkdir(this.#mp(uploadId), { recursive: true });
    await writeFile(join(this.#mp(uploadId), 'meta.json'), JSON.stringify({ key, contentType }));
    return { uploadId };
  }

  async signPart(
    key: string,
    uploadId: string,
    partNumber: number,
    bytes: number,
    expiresAt: Date,
  ) {
    return this.#url('/o/part', {
      k: key,
      u: uploadId,
      n: String(partNumber),
      b: String(bytes),
      e: String(Math.floor(expiresAt.getTime() / 1000)),
    });
  }

  async #meta(uploadId: string): Promise<{ key: string } | undefined> {
    try {
      return JSON.parse(await readFile(join(this.#mp(uploadId), 'meta.json'), 'utf8')) as {
        key: string;
      };
    } catch {
      return undefined;
    }
  }

  /** Called by the content server for a verified part URL. Writes atomically; enforces the signed size. */
  async putPart(
    key: string,
    uploadId: string,
    partNumber: number,
    bytes: number,
    body: NodeJS.ReadableStream,
  ) {
    const meta = await this.#meta(uploadId);
    if (!meta || meta.key !== key)
      throw Object.assign(new Error('no such upload'), { statusCode: 404 });
    if (bytes < 1 || bytes > MAX_PART)
      throw Object.assign(new Error('bad size'), { statusCode: 400 });
    const tmp = join(this.#mp(uploadId), `${partNumber}.${randomBytes(6).toString('hex')}.tmp`);
    const hash = createHash('md5');
    let seen = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        seen += chunk.length;
        if (seen > bytes) return cb(Object.assign(new Error('too large'), { statusCode: 400 }));
        hash.update(chunk);
        cb(null, chunk);
      },
    });
    try {
      await pipeline(body, counter, createWriteStream(tmp));
      if (seen !== bytes) throw Object.assign(new Error('size mismatch'), { statusCode: 400 });
      const etag = hash.digest('hex');
      await rename(tmp, join(this.#mp(uploadId), `part-${partNumber}-${etag}`));
      // A re-sent part replaces any earlier copy of the same number.
      for (const f of await readdir(this.#mp(uploadId)))
        if (f.startsWith(`part-${partNumber}-`) && f !== `part-${partNumber}-${etag}`)
          await rm(join(this.#mp(uploadId), f), { force: true });
      return etag;
    } catch (e) {
      await rm(tmp, { force: true });
      throw e;
    }
  }

  async listParts(key: string, uploadId: string): Promise<UploadedPart[]> {
    const meta = await this.#meta(uploadId);
    if (!meta || meta.key !== key) return [];
    const out: UploadedPart[] = [];
    for (const f of await readdir(this.#mp(uploadId))) {
      const m = /^part-(\d+)-([0-9a-f]{32})$/.exec(f);
      if (!m) continue;
      out.push({
        partNumber: Number(m[1]),
        etag: m[2]!,
        size: (await stat(join(this.#mp(uploadId), f))).size,
      });
    }
    return out.sort((a, b) => a.partNumber - b.partNumber);
  }

  async completeMultipart(
    key: string,
    uploadId: string,
    parts: ReadonlyArray<{ partNumber: number; etag: string }>,
  ) {
    const meta = await this.#meta(uploadId);
    if (!meta || meta.key !== key) throw new Error('no such upload');
    await mkdir(join(this.#root, 'objects'), { recursive: true });
    const tmp = `${this.#obj(key)}.${randomBytes(6).toString('hex')}.tmp`;
    const out = createWriteStream(tmp);
    try {
      for (const p of parts) {
        if (!/^[0-9a-f]{32}$/.test(p.etag)) throw new Error('bad etag');
        for await (const chunk of createReadStream(
          join(this.#mp(uploadId), `part-${p.partNumber}-${p.etag}`),
        ))
          if (!out.write(chunk)) await once(out, 'drain');
      }
      await new Promise<void>((res, rej) => out.end((e?: Error | null) => (e ? rej(e) : res())));
      await rename(tmp, this.#obj(key));
    } catch (e) {
      out.destroy();
      await rm(tmp, { force: true });
      throw e;
    }
    await rm(this.#mp(uploadId), { recursive: true, force: true });
    return { size: (await stat(this.#obj(key))).size };
  }

  async abortMultipart(_key: string, uploadId: string) {
    await rm(this.#mp(uploadId), { recursive: true, force: true });
  }

  async head(key: string) {
    try {
      return { size: (await stat(this.#obj(key))).size };
    } catch {
      return undefined;
    }
  }

  async read(key: string): Promise<AsyncIterable<Uint8Array>> {
    return createReadStream(this.#obj(key));
  }

  async signDownload(key: string, o: SignedDownload) {
    return this.#url('/o/get', {
      k: key,
      e: String(Math.floor(o.expiresAt.getTime() / 1000)),
      d: contentDisposition(o.disposition, o.filename),
      t: o.contentType,
    });
  }

  /** Path of a stored object for the content server (only after signature verification). */
  objectPath(key: string) {
    return this.#obj(key);
  }

  async delete(key: string) {
    await rm(this.#obj(key), { force: true });
  }
}

/** Response headers for untrusted bytes. PDFs need the browser viewer, so only they skip the CSP sandbox. */
export function untrustedContentHeaders(
  contentType: string,
  disposition: string,
  frameAncestor: string,
) {
  const pdf = contentType === 'application/pdf';
  return {
    'content-type': contentType,
    'content-disposition': disposition,
    'x-content-type-options': 'nosniff',
    'cache-control': 'private, no-store',
    'referrer-policy': 'no-referrer',
    'cross-origin-resource-policy': 'cross-origin',
    'content-security-policy': `default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors ${frameAncestor}${pdf ? '' : '; sandbox'}`,
  };
}

/**
 * The isolated content origin for {@link LocalObjectStore}. Accepts signed part uploads (CORS for the portal
 * origin only) and serves signed downloads with safe headers. It has no other routes and no access to the API's
 * stores or sessions.
 */
export async function buildContentApp(
  store: LocalObjectStore,
  opts: { allowedOrigin: string; now?: () => number; logger?: boolean },
): Promise<FastifyInstance> {
  const now = opts.now ?? Date.now;
  const app = Fastify({ logger: opts.logger ?? false, bodyLimit: 1024 });
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('*', (_req, payload, done) => done(null, payload));
  const cors = (origin: string | undefined) =>
    origin === opts.allowedOrigin
      ? {
          'access-control-allow-origin': opts.allowedOrigin,
          'access-control-expose-headers': 'ETag',
          vary: 'Origin',
        }
      : { vary: 'Origin' };

  app.options('/o/part', async (req, reply) =>
    reply
      .headers({
        ...cors(req.headers.origin),
        'access-control-allow-methods': 'PUT',
        'access-control-allow-headers': 'content-type',
        'access-control-max-age': '600',
      })
      .status(204)
      .send(),
  );

  app.put('/o/part', async (req, reply) => {
    reply.headers(cors(req.headers.origin));
    const p = store.verify(req.query as Record<string, unknown>, now());
    if (!p)
      return reply.status(403).send({ code: 'forbidden', message: 'invalid or expired signature' });
    const bytes = Number(p['b']);
    if (Number(req.headers['content-length']) !== bytes)
      return reply
        .status(400)
        .send({ code: 'invalid_request', message: 'content-length must match the signed size' });
    try {
      const etag = await store.putPart(
        p['k']!,
        p['u']!,
        Number(p['n']),
        bytes,
        req.body as NodeJS.ReadableStream,
      );
      return reply.header('etag', `"${etag}"`).status(200).send();
    } catch (e) {
      const status = (e as { statusCode?: number }).statusCode ?? 500;
      return reply
        .status(status)
        .send({ code: status === 404 ? 'not_found' : 'invalid_request', message: 'upload failed' });
    }
  });

  app.get('/o/get', async (req, reply) => {
    const p = store.verify(req.query as Record<string, unknown>, now());
    if (!p)
      return reply
        .status(403)
        .type('text/plain')
        .send('This download link is invalid or has expired.');
    const path = store.objectPath(p['k']!);
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch {
      return reply.status(404).type('text/plain').send('Not found.');
    }
    // CORS lets the portal read back its own drafts for re-editing; the signature, not the origin, is the authority.
    return reply
      .headers({
        ...untrustedContentHeaders(p['t']!, p['d']!, opts.allowedOrigin),
        ...cors(req.headers.origin),
        'content-length': String(size),
      })
      .send(createReadStream(path));
  });

  app.setNotFoundHandler((_req, reply) => reply.status(404).type('text/plain').send('Not found.'));
  return app;
}
