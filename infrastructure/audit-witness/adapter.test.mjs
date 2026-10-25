import { test, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { S3Client, PutObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { computeAnchor } from '../../packages/audit/src/index.ts';
process.env.AWS_REGION = 'eu-west-1';
process.env.WITNESS_TOKEN = 'a'.repeat(32);
process.env.WITNESS_BUCKET = 'synthetic-witness';
process.env.WITNESS_RETENTION_DAYS = '365';
const { handler } = await import('./lambda.mjs');
afterEach(() => mock.restoreAll());
const event = () => ({
  rawPath: '/anchors',
  requestContext: { http: { method: 'POST' } },
  headers: { authorization: `Bearer ${'a'.repeat(32)}`, 'content-type': 'application/json' },
  body: JSON.stringify({
    v: 1,
    created_at: '2026-10-24T12:00:00.000Z',
    anchor: computeAnchor([]),
    chains: [],
  }),
});

test('AWS adapter conditionally creates, checks the exact locked version and retries across invocations', async () => {
  let stored,
    writes = 0;
  mock.method(S3Client.prototype, 'send', async (command, options) => {
    assert.ok(options.abortSignal instanceof globalThis.AbortSignal);
    assert.equal(command.input.Bucket, 'synthetic-witness');
    if (command instanceof PutObjectCommand) {
      assert.equal(command.input.IfNoneMatch, '*');
      assert.equal(command.input.ObjectLockMode, undefined);
      assert.equal(command.input.ObjectLockRetainUntilDate, undefined);
      assert.equal(command.input.ChecksumAlgorithm, 'SHA256');
      if (stored) throw { $metadata: { httpStatusCode: 412 } };
      stored = command.input;
      writes++;
      return { VersionId: 'retained-version' };
    }
    assert.ok(command instanceof HeadObjectCommand);
    assert.equal(command.input.Key, stored.Key);
    return {
      VersionId: 'retained-version',
      Metadata: stored.Metadata,
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: new Date(Date.now() + 366 * 86400000),
    };
  });
  const a = await handler(event());
  const b = await handler(event());
  assert.equal(a.statusCode, 201);
  assert.equal(b.statusCode, 201);
  assert.equal(a.headers['x-witness-receipt'], b.headers['x-witness-receipt']);
  assert.equal(writes, 1);
});
test('unauthenticated requests make no AWS calls', async () => {
  const spy = mock.method(S3Client.prototype, 'send', async () => {
    throw new Error('must not call');
  });
  const r = await handler({ ...event(), headers: { authorization: 'wrong' } });
  assert.equal(r.statusCode, 401);
  assert.equal(spy.mock.callCount(), 0);
});
test('provider failures remain fixed errors without secret values', async () => {
  mock.method(S3Client.prototype, 'send', async () => {
    throw new Error('SECRET_PROVIDER_DETAIL');
  });
  const r = await handler(event());
  assert.equal(r.statusCode, 503);
  assert.ok(!JSON.stringify(r).includes('SECRET'));
});
test('a successful write is not acknowledged when retention is absent', async () => {
  let metadata;
  mock.method(S3Client.prototype, 'send', async (command) => {
    if (command instanceof PutObjectCommand) {
      metadata = command.input.Metadata;
      return { VersionId: 'v1' };
    }
    return { VersionId: 'v1', Metadata: metadata };
  });
  assert.equal((await handler(event())).statusCode, 503);
});
test('an ambiguous committed write is recovered on retry without creating another version', async () => {
  let stored;
  mock.method(S3Client.prototype, 'send', async (command) => {
    if (command instanceof PutObjectCommand) {
      if (stored) throw { $metadata: { httpStatusCode: 412 } };
      stored = command.input;
      throw new Error('synthetic lost acknowledgement');
    }
    return {
      VersionId: 'committed-version',
      Metadata: stored.Metadata,
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: new Date(Date.now() + 366 * 86400000),
    };
  });
  assert.equal((await handler(event())).statusCode, 503);
  const recovered = await handler(event());
  assert.equal(recovered.statusCode, 201);
  assert.equal(
    Buffer.from(recovered.headers['x-witness-receipt'].split(':')[2], 'base64url').toString(),
    'committed-version',
  );
});
