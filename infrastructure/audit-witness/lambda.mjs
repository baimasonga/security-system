import { S3Client, HeadObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { createWitnessReceiver } from '../../tools/audit-witness/receiver.ts';
import { createLockedStore } from '../../tools/audit-witness/locked-store.ts';

const client = new S3Client({ maxAttempts: 1 });
export async function handler(event) {
  try {
    const bucket = process.env.WITNESS_BUCKET;
    if (!bucket) throw new Error('missing bucket');
    const signal = globalThis.AbortSignal.timeout(8000);
    const store = createLockedStore(
      {
        async head(key, version) {
          try {
            const r = await client.send(
              new HeadObjectCommand({
                Bucket: bucket,
                Key: key,
                ...(version ? { VersionId: version } : {}),
              }),
              { abortSignal: signal },
            );
            return {
              version: r.VersionId ?? '',
              digest: r.Metadata?.['manifest-sha256'] ?? '',
              mode: r.ObjectLockMode ?? '',
              retainUntil: r.ObjectLockRetainUntilDate ?? new Date(0),
            };
          } catch (e) {
            if (e?.$metadata?.httpStatusCode === 404) return undefined;
            throw e;
          }
        },
        async put(key, body, digest) {
          try {
            const r = await client.send(
              new PutObjectCommand({
                Bucket: bucket,
                Key: key,
                Body: body,
                ContentType: 'application/json',
                IfNoneMatch: '*',
                ChecksumAlgorithm: 'SHA256',
                Metadata: { 'manifest-sha256': digest },
              }),
              { abortSignal: signal },
            );
            if (!r.VersionId) throw new Error('missing version');
            return r.VersionId;
          } catch (e) {
            if (e?.$metadata?.httpStatusCode === 412) return undefined;
            throw e;
          }
        },
      },
      Number(process.env.WITNESS_RETENTION_DAYS),
    );
    const receiver = createWitnessReceiver({ token: process.env.WITNESS_TOKEN ?? '', store });
    return await receiver({
      method: event.requestContext?.http?.method ?? '',
      path: event.rawPath ?? '',
      authorization: event.headers?.authorization ?? '',
      contentType: event.headers?.['content-type'] ?? '',
      body: event.body ?? '',
      base64: event.isBase64Encoded === true,
    });
  } catch {
    return {
      statusCode: 503,
      headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' },
      body: 'witness unavailable',
    };
  }
}
