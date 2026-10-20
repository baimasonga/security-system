import { createHash, createHmac } from 'node:crypto';
import { Readable } from 'node:stream';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import {
  contentDisposition,
  type ObjectStore,
  type SignedDownload,
  type UploadedPart,
} from '@trust/sharing';

// S3-compatible private object storage (Cloudflare R2, AWS S3, MinIO) with AWS Signature Version 4, implemented on
// node:crypto (no SDK). The bucket is private; browsers reach it only through short-lived presigned URLs, and the
// bucket's own origin is the isolated content origin. Requests go only to the operator-configured endpoint.
//
// Verified against the AWS SigV4 example, a protocol fake and synthetic live multipart/private-access checks.
// Provider endpoint/CORS and quarantine acceptance remain deployment-specific checks (docs/deploy).

export interface S3Config {
  endpoint: string; // e.g. https://<account>.r2.cloudflarestorage.com
  region: string; // 'auto' for R2
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
}

const enc = (s: string) =>
  encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
const sha256 = (d: string | Buffer) => createHash('sha256').update(d).digest('hex');
const hmac = (k: Buffer | string, d: string) => createHmac('sha256', k).update(d).digest();
const amzDate = (d: Date) =>
  d
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}/, '');

export class SigV4 {
  readonly #c: S3Config;
  constructor(c: S3Config) {
    this.#c = c;
  }

  #key(date: string) {
    return hmac(
      hmac(hmac(hmac(`AWS4${this.#c.secretAccessKey}`, date), this.#c.region), 's3'),
      'aws4_request',
    );
  }

  /** RFC 3986 query encoding used both for signing and for the request URL itself. */
  query(q: Record<string, string>) {
    return this.#canonicalQuery(q);
  }

  #canonicalQuery(q: Record<string, string>) {
    return Object.keys(q)
      .sort()
      .map((k) => `${enc(k)}=${enc(q[k]!)}`)
      .join('&');
  }

  /** Bucket-qualified endpoints use virtual-host addressing; others retain path addressing. */
  path(key: string) {
    const virtualHost = new URL(this.#c.endpoint).hostname.startsWith(`${this.#c.bucket}.`);
    return `${virtualHost ? '' : `/${enc(this.#c.bucket)}`}/${key.split('/').map(enc).join('/')}`;
  }

  /** Presigned URL (query authentication). `headers` are additional signed headers the client must send. */
  presign(
    method: string,
    path: string,
    query: Record<string, string>,
    expiresSeconds: number,
    now: Date,
    headers: Record<string, string> = {},
  ) {
    const url = new URL(this.#c.endpoint);
    const host = url.host;
    const t = amzDate(now);
    const date = t.slice(0, 8);
    const scope = `${date}/${this.#c.region}/s3/aws4_request`;
    const signedHeaders = {
      host,
      ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    };
    const names = Object.keys(signedHeaders).sort();
    const q: Record<string, string> = {
      ...query,
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Credential': `${this.#c.accessKeyId}/${scope}`,
      'X-Amz-Date': t,
      'X-Amz-Expires': String(expiresSeconds),
      'X-Amz-SignedHeaders': names.join(';'),
    };
    const canonical = [
      method,
      path,
      this.#canonicalQuery(q),
      names
        .map((n) => `${n}:${String(signedHeaders[n as keyof typeof signedHeaders]).trim()}\n`)
        .join(''),
      names.join(';'),
      'UNSIGNED-PAYLOAD',
    ].join('\n');
    const toSign = ['AWS4-HMAC-SHA256', t, scope, sha256(canonical)].join('\n');
    const sig = createHmac('sha256', this.#key(date)).update(toSign).digest('hex');
    return `${url.protocol}//${host}${path}?${this.#canonicalQuery({ ...q, 'X-Amz-Signature': sig })}`;
  }

  /** Header authentication for server-side requests. */
  authorize(method: string, path: string, query: Record<string, string>, body: Buffer, now: Date) {
    const host = new URL(this.#c.endpoint).host;
    const t = amzDate(now);
    const date = t.slice(0, 8);
    const scope = `${date}/${this.#c.region}/s3/aws4_request`;
    const payloadHash = sha256(body);
    const headers: Record<string, string> = {
      host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': t,
    };
    const names = Object.keys(headers).sort();
    const canonical = [
      method,
      path,
      this.#canonicalQuery(query),
      names.map((n) => `${n}:${headers[n]}\n`).join(''),
      names.join(';'),
      payloadHash,
    ].join('\n');
    const toSign = ['AWS4-HMAC-SHA256', t, scope, sha256(canonical)].join('\n');
    const sig = createHmac('sha256', this.#key(date)).update(toSign).digest('hex');
    return {
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': t,
      authorization: `AWS4-HMAC-SHA256 Credential=${this.#c.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${sig}`,
    };
  }
}

function tag(xml: string, name: string): string | undefined {
  const open = `<${name}>`;
  const start = xml.indexOf(open);
  if (start < 0) return undefined;
  const end = xml.indexOf(`</${name}>`, start + open.length);
  return end < 0 ? undefined : xml.slice(start + open.length, end);
}
const unxml = (s: string) =>
  s.replace(/&(quot|lt|gt|apos|amp|#x[0-9a-f]+|#[0-9]+);/gi, (entity, value: string) => {
    const named: Record<string, string> = { quot: '"', lt: '<', gt: '>', apos: "'", amp: '&' };
    if (!value.startsWith('#')) return named[value] ?? entity;
    const hex = value[1]?.toLowerCase() === 'x';
    const point = Number.parseInt(value.slice(hex ? 2 : 1), hex ? 16 : 10);
    return point === 9 ||
      point === 10 ||
      point === 13 ||
      (point >= 0x20 && point <= 0xd7ff) ||
      (point >= 0xe000 && point <= 0xfffd) ||
      (point >= 0x10000 && point <= 0x10ffff)
      ? String.fromCodePoint(point)
      : entity;
  });
const escapeXml = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

export class S3ObjectStore implements ObjectStore {
  readonly kind = 's3';
  readonly minPartBytes = 5 * 1024 * 1024;
  readonly #c: S3Config;
  readonly #sig: SigV4;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;

  constructor(c: S3Config, opts: { fetch?: typeof fetch; now?: () => Date } = {}) {
    const u = new URL(c.endpoint);
    if (u.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(u.hostname))
      throw new Error('object storage endpoint must use https');
    this.#c = c;
    this.#sig = new SigV4(c);
    this.#fetch = opts.fetch ?? fetch;
    this.#now = opts.now ?? (() => new Date());
  }

  async #req(
    method: string,
    key: string,
    query: Record<string, string>,
    body = Buffer.alloc(0),
    ok: number[] = [200],
  ) {
    const path = this.#sig.path(key);
    const qs = Object.keys(query).length ? `?${this.#sig.query(query)}` : '';
    const res = await this.#fetch(`${new URL(this.#c.endpoint).origin}${path}${qs}`, {
      method,
      headers: {
        ...this.#sig.authorize(method, path, query, body, this.#now()),
        ...(body.length ? { 'content-type': 'application/xml' } : {}),
      },
      ...(body.length ? { body } : {}),
      redirect: 'error',
    });
    if (!ok.includes(res.status)) {
      const text = await res.text().catch(() => '');
      throw Object.assign(new Error(`object storage ${method} failed`), {
        code: tag(text, 'Code') ?? String(res.status),
      });
    }
    return res;
  }

  async createMultipart(key: string, contentType: string) {
    void contentType; // served type is fixed per download via response-content-type
    const xml = await (await this.#req('POST', key, { uploads: '' })).text();
    const uploadId = tag(xml, 'UploadId');
    if (!uploadId) throw new Error('object storage returned no upload id');
    return { uploadId: unxml(uploadId) };
  }

  async signPart(
    key: string,
    uploadId: string,
    partNumber: number,
    bytes: number,
    expiresAt: Date,
  ) {
    const now = this.#now();
    const ttl = Math.max(
      1,
      Math.min(604_800, Math.floor((expiresAt.getTime() - now.getTime()) / 1000)),
    );
    return this.#sig.presign(
      'PUT',
      this.#sig.path(key),
      { partNumber: String(partNumber), uploadId },
      ttl,
      now,
      {
        'content-length': String(bytes),
      },
    );
  }

  async listParts(key: string, uploadId: string): Promise<UploadedPart[]> {
    const out: UploadedPart[] = [];
    let marker = '0';
    for (let page = 0; page < 20; page++) {
      const res = await this.#req(
        'GET',
        key,
        { uploadId, 'part-number-marker': marker, 'max-parts': '1000' },
        Buffer.alloc(0),
        [200, 404],
      );
      if (res.status === 404) return [];
      const xml = await res.text();
      for (const m of xml.matchAll(/<Part>([\s\S]*?)<\/Part>/g)) {
        const p = m[1]!;
        out.push({
          partNumber: Number(tag(p, 'PartNumber')),
          etag: unxml(tag(p, 'ETag') ?? '').replace(/^"|"$/g, ''),
          size: Number(tag(p, 'Size')),
        });
      }
      if (tag(xml, 'IsTruncated') !== 'true') break;
      marker = tag(xml, 'NextPartNumberMarker') ?? marker;
    }
    return out;
  }

  async completeMultipart(
    key: string,
    uploadId: string,
    parts: ReadonlyArray<{ partNumber: number; etag: string }>,
  ) {
    const body = Buffer.from(
      `<CompleteMultipartUpload>${parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>"${escapeXml(p.etag)}"</ETag></Part>`).join('')}</CompleteMultipartUpload>`,
    );
    const xml = await (await this.#req('POST', key, { uploadId }, body)).text();
    // S3 can report a failed completion inside a 200 response.
    if (/<Error>/.test(xml))
      throw Object.assign(new Error('object storage completion failed'), {
        code: tag(xml, 'Code'),
      });
    const h = await this.head(key);
    if (!h) throw new Error('completed object not found');
    return h;
  }

  async abortMultipart(key: string, uploadId: string) {
    await this.#req('DELETE', key, { uploadId }, Buffer.alloc(0), [200, 204, 404]);
  }

  async head(key: string) {
    const res = await this.#req('HEAD', key, {}, Buffer.alloc(0), [200, 404]);
    return res.status === 404 ? undefined : { size: Number(res.headers.get('content-length')) };
  }

  async read(key: string): Promise<AsyncIterable<Uint8Array>> {
    const res = await this.#req('GET', key, {});
    if (!res.body) throw new Error('empty object body');
    return Readable.fromWeb(res.body as unknown as WebReadableStream<Uint8Array>);
  }

  async signDownload(key: string, o: SignedDownload) {
    const now = this.#now();
    const ttl = Math.max(1, Math.floor((o.expiresAt.getTime() - now.getTime()) / 1000));
    return this.#sig.presign(
      'GET',
      this.#sig.path(key),
      {
        'response-content-disposition': contentDisposition(o.disposition, o.filename),
        'response-content-type': o.contentType,
        'response-cache-control': 'private, no-store',
      },
      ttl,
      now,
    );
  }

  async delete(key: string) {
    await this.#req('DELETE', key, {}, Buffer.alloc(0), [200, 204, 404]);
  }
}
