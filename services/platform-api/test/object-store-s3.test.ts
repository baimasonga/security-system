import { describe, expect, it } from 'vitest';
import { S3ObjectStore, SigV4 } from '../src/integrations/object-store-s3.ts';

const AWS = {
  endpoint: 'https://examplebucket.s3.amazonaws.com',
  region: 'us-east-1',
  bucket: 'examplebucket',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};

describe('S3 SigV4', () => {
  it('reproduces the AWS documented presigned-URL example exactly', () => {
    // https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html (GET test.txt, 86400 s)
    const url = new SigV4(AWS).presign(
      'GET',
      '/test.txt',
      {},
      86400,
      new Date('2013-05-24T00:00:00Z'),
    );
    const q = new URL(url).searchParams;
    expect(q.get('X-Amz-Credential')).toBe(
      'AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request',
    );
    expect(q.get('X-Amz-SignedHeaders')).toBe('host');
    expect(q.get('X-Amz-Signature')).toBe(
      'aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404',
    );
  });

  it('binds part uploads to their exact size and download URLs to safe response headers', async () => {
    const store = new S3ObjectStore(
      {
        ...AWS,
        endpoint: 'https://acct.r2.cloudflarestorage.com',
        region: 'auto',
        bucket: 'shares',
      },
      { now: () => new Date('2026-03-01T00:00:00Z') },
    );
    const part = new URL(
      await store.signPart('o/org_1/blb_1', 'up-1', 3, 1234, new Date('2026-03-01T00:15:00Z')),
    );
    expect(part.pathname).toBe('/shares/o/org_1/blb_1');
    expect(part.searchParams.get('partNumber')).toBe('3');
    expect(part.searchParams.get('X-Amz-SignedHeaders')).toBe('content-length;host');
    expect(part.searchParams.get('X-Amz-Expires')).toBe('900');
    const dl = new URL(
      await store.signDownload('o/org_1/blb_1', {
        filename: 'Q1 report.pdf',
        contentType: 'application/pdf',
        disposition: 'attachment',
        expiresAt: new Date('2026-03-01T00:01:00Z'),
      }),
    );
    expect(dl.searchParams.get('response-content-disposition')).toBe(
      `attachment; filename="Q1 report.pdf"; filename*=UTF-8''Q1%20report.pdf`,
    );
    expect(dl.searchParams.get('response-content-type')).toBe('application/pdf');
    expect(dl.searchParams.get('X-Amz-Expires')).toBe('60');
  });

  it('refuses a plaintext endpoint', () => {
    expect(() => new S3ObjectStore({ ...AWS, endpoint: 'http://storage.example.com' })).toThrow(
      'https',
    );
  });

  it('speaks the multipart protocol to the configured endpoint only', async () => {
    const calls: Array<{ method: string; url: string; auth: string | null; body: string }> = [];
    const objects = new Map<string, Buffer>();
    const fake: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      const auth = new Headers(init?.headers).get('authorization');
      const body = init?.body ? Buffer.from(init.body as Buffer).toString() : '';
      calls.push({ method, url: url.toString(), auth, body });
      expect(auth).toMatch(
        /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20260301\/auto\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/,
      );
      if (method === 'POST' && url.searchParams.has('uploads'))
        return new Response(
          '<InitiateMultipartUploadResult><UploadId>abc&amp;1</UploadId></InitiateMultipartUploadResult>',
        );
      if (method === 'GET' && url.searchParams.has('uploadId'))
        return new Response(
          '<ListPartsResult><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><ETag>&quot;e1&quot;</ETag><Size>5</Size></Part></ListPartsResult>',
        );
      if (method === 'POST' && url.searchParams.has('uploadId')) {
        objects.set(url.pathname, Buffer.from('hello'));
        return new Response('<CompleteMultipartUploadResult/>');
      }
      if (method === 'HEAD')
        return objects.has(url.pathname)
          ? new Response(null, { headers: { 'content-length': '5' } })
          : new Response(null, { status: 404 });
      if (method === 'DELETE') return new Response(null, { status: 204 });
      return new Response('<Error><Code>NotImplemented</Code></Error>', { status: 501 });
    };
    const store = new S3ObjectStore(
      {
        ...AWS,
        endpoint: 'https://acct.r2.cloudflarestorage.com',
        region: 'auto',
        bucket: 'shares',
      },
      { fetch: fake, now: () => new Date('2026-03-01T00:00:00Z') },
    );
    const { uploadId } = await store.createMultipart('o/org_1/blb_1', 'application/pdf');
    expect(uploadId).toBe('abc&1');
    expect(await store.listParts('o/org_1/blb_1', uploadId)).toEqual([
      { partNumber: 1, etag: 'e1', size: 5 },
    ]);
    expect(
      await store.completeMultipart('o/org_1/blb_1', uploadId, [{ partNumber: 1, etag: 'e1' }]),
    ).toEqual({ size: 5 });
    expect(calls.find((c) => c.method === 'POST' && c.url.includes('uploadId'))!.body).toBe(
      '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"e1"</ETag></Part></CompleteMultipartUpload>',
    );
    expect(await store.head('o/org_1/missing')).toBeUndefined();
    await store.delete('o/org_1/blb_1');
    await store.abortMultipart('o/org_1/blb_1', uploadId);
    expect(new Set(calls.map((c) => new URL(c.url).host))).toEqual(
      new Set(['acct.r2.cloudflarestorage.com']),
    );
    expect(calls.find((c) => c.url.includes('uploadId=abc'))!.url).toContain('uploadId=abc%261');
  });
});
