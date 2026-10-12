import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { KeyRing, signJws } from '@trust/crypto';
import { SecureUpdateClient, type UpdateManifest } from '../src/index.ts';
async function setup(bytes = Buffer.from('verified installer'), paused = false) {
  const now = 1800000000,
    ring = new KeyRing();
  const r = ring.generate('license'),
    k = ring.generate('license');
  ring.activate(r.kid);
  ring.activate(k.kid);
  const manifest: UpdateManifest = {
    schema: 1,
    product: 'editor',
    platform: 'windows-x64',
    channel: 'stable',
    sequence: 1,
    version: '1.0',
    minimum_sequence: 1,
    issued_at: now - 1,
    expires: now + 100,
    paused,
    artifact: {
      url: 'https://updates.example/artifact',
      size: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      sbom_sha256: 'a'.repeat(64),
      provenance_sha256: 'b'.repeat(64),
    },
  };
  const envelope = {
    signatures: [
      await signJws(
        { ...manifest },
        { kid: k.kid, typ: 'trust-update-manifest+jws' },
        ring.custody,
      ),
    ],
  };
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => new Response(bytes));
  const sdk = new SecureUpdateClient({
    root: {
      schema: 1,
      version: 1,
      expires: now + 100,
      root: { threshold: 1, keys: [{ kid: r.kid, jwk: r.publicJwk }] },
      release: { threshold: 1, keys: [{ kid: k.kid, jwk: k.publicJwk }] },
      artifact_origins: ['https://updates.example'],
    },
    product: 'editor',
    platform: 'windows-x64',
    channel: 'stable',
    store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
    now: () => new Date(now * 1000),
    fetch: fetcher,
  });
  return { sdk, envelope, fetcher };
}
it('stages only hash/size-verified bytes with redirects disabled', async () => {
  const s = await setup(),
    dir = await mkdtemp(join(tmpdir(), 'update-test-'));
  try {
    const result = await s.sdk.stageArtifact(s.envelope, dir);
    expect(await readFile(result.path, 'utf8')).toBe('verified installer');
    expect(s.fetcher.mock.calls[0]?.[1]?.redirect).toBe('error');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
it.each(['tampered installer', 'x', 'verified installer extra'])(
  'removes corrupt, truncated or oversized downloads',
  async (bytes) => {
    const s = await setup(),
      dir = await mkdtemp(join(tmpdir(), 'update-test-'));
    s.fetcher.mockResolvedValue(new Response(bytes));
    try {
      await expect(s.sdk.stageArtifact(s.envelope, dir)).rejects.toThrow();
      expect(await readdir(dir)).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
it('does not download paused releases', async () => {
  const s = await setup(undefined, true),
    dir = await mkdtemp(join(tmpdir(), 'update-test-'));
  try {
    await expect(s.sdk.stageArtifact(s.envelope, dir)).rejects.toThrow('paused');
    expect(s.fetcher).not.toHaveBeenCalled();
    expect(await readdir(dir)).toEqual([]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
it('cleans staging files after interrupted downloads', async () => {
  const s = await setup(),
    dir = await mkdtemp(join(tmpdir(), 'update-test-'));
  s.fetcher.mockImplementation(
    async () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new Uint8Array([1]));
            c.error(new Error('interrupted'));
          },
        }),
      ),
  );
  try {
    await expect(s.sdk.stageArtifact(s.envelope, dir)).rejects.toThrow();
    expect(await readdir(dir)).toEqual([]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

it('fetches a signed feed only from an allowed origin and rejects oversized responses', async () => {
  const s = await setup();
  s.fetcher.mockImplementation(async () => Response.json(s.envelope));
  expect(
    (await s.sdk.checkForUpdates('https://updates.example/stable.json')).manifest.sequence,
  ).toBe(1);
  expect(s.fetcher.mock.calls[0]?.[1]?.redirect).toBe('error');
  await expect(s.sdk.checkForUpdates('https://attacker.example/stable.json')).rejects.toThrow(
    'metadata origin',
  );
  expect(s.fetcher).toHaveBeenCalledTimes(1);
  s.fetcher.mockImplementation(async () => new Response('x'.repeat(512 * 1024 + 1)));
  await expect(s.sdk.checkForUpdates('https://updates.example/stable.json')).rejects.toThrow(
    'metadata size',
  );
});
