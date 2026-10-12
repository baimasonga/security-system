import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { KeyRing, signJws } from '@trust/crypto';
import { SecureUpdateClient, type UpdateRoot, type UpdateManifest } from '../src/index.ts';
const now = 1_800_000_000;
function setup() {
  const ring = new KeyRing();
  const rootKey = ring.generate('license');
  ring.activate(rootKey.kid);
  const releaseKey = ring.generate('license');
  ring.activate(releaseKey.kid);
  const root: UpdateRoot = {
    schema: 1,
    version: 1,
    expires: now + 3600,
    root: { threshold: 1, keys: [{ kid: rootKey.kid, jwk: rootKey.publicJwk }] },
    release: { threshold: 1, keys: [{ kid: releaseKey.kid, jwk: releaseKey.publicJwk }] },
    artifact_origins: ['https://updates.example'],
  };
  const artifact = Buffer.from('installer');
  const digest = createHash('sha256').update(artifact).digest('hex');
  const manifest: UpdateManifest = {
    schema: 1,
    product: 'editor',
    platform: 'windows-x64',
    channel: 'stable',
    sequence: 2,
    version: '1.2.0',
    minimum_sequence: 1,
    issued_at: now - 1,
    expires: now + 300,
    paused: false,
    artifact: {
      url: 'https://updates.example/' + digest,
      size: artifact.length,
      sha256: digest,
      sbom_sha256: 'a'.repeat(64),
      provenance_sha256: 'b'.repeat(64),
    },
  };
  const values = new Map<string, string>();
  const sdk = new SecureUpdateClient({
    root,
    product: manifest.product,
    platform: manifest.platform,
    channel: manifest.channel,
    store: {
      get: async (k) => values.get(k),
      set: async (k, v) => {
        values.set(k, v);
      },
      delete: async (k) => {
        values.delete(k);
      },
    },
    now: () => new Date(now * 1000),
  });
  const sign = async (
    m: UpdateManifest,
    kid = releaseKey.kid,
    typ = 'trust-update-manifest+jws',
  ) => ({ signatures: [await signJws({ ...m }, { kid, typ }, ring.custody)] });
  return { ring, rootKey, releaseKey, root, manifest, sdk, sign, values, artifact };
}
it('accepts authentic releases and exact retries, persisting rollback protection', async () => {
  const s = setup();
  const envelope = await s.sign(s.manifest);
  expect(await s.sdk.verifyManifest(envelope)).toEqual(s.manifest);
  expect(await s.sdk.verifyManifest(envelope)).toEqual(s.manifest);
  await expect(s.sdk.verifyManifest(await s.sign({ ...s.manifest, sequence: 1 }))).rejects.toThrow(
    'rollback',
  );
  await expect(
    s.sdk.verifyManifest(await s.sign({ ...s.manifest, version: 'altered' })),
  ).rejects.toThrow('equivocation');
});
it.each(['product', 'platform', 'channel'] as const)(
  'rejects a wrong %s binding',
  async (field) => {
    const s = setup();
    await expect(
      s.sdk.verifyManifest(await s.sign({ ...s.manifest, [field]: 'wrong' })),
    ).rejects.toThrow('binding');
  },
);
it.each([
  { expires: now },
  { issued_at: now + 61 },
  { minimum_sequence: 3 },
  { sequence: 0 },
  {
    artifact: {
      url: 'http://updates.example/a',
      size: 1,
      sha256: 'a'.repeat(64),
      sbom_sha256: 'b'.repeat(64),
      provenance_sha256: 'c'.repeat(64),
    },
  },
])('rejects stale, future, malformed and unsafe metadata', async (patch) => {
  const s = setup();
  await expect(s.sdk.verifyManifest(await s.sign({ ...s.manifest, ...patch }))).rejects.toThrow();
  expect(s.values.size).toBe(0);
});
it('rejects license-purpose and root-role signatures for a release', async () => {
  const s = setup();
  await expect(
    s.sdk.verifyManifest(await s.sign(s.manifest, s.releaseKey.kid, 'trust-lease+jws')),
  ).rejects.toThrow();
  await expect(s.sdk.verifyManifest(await s.sign(s.manifest, s.rootKey.kid))).rejects.toThrow();
});
it('requires old and new thresholds for sequential root rotation', async () => {
  const s = setup();
  const replacement = s.ring.generate('license');
  s.ring.activate(replacement.kid);
  const next = {
    ...s.root,
    version: 2,
    root: { threshold: 1, keys: [{ kid: replacement.kid, jwk: replacement.publicJwk }] },
  };
  const token = async (kid: string) =>
    signJws({ ...next }, { kid, typ: 'trust-update-root+jws' }, s.ring.custody);
  await expect(s.sdk.rotateRoot({ signatures: [await token(s.rootKey.kid)] })).rejects.toThrow();
  await s.sdk.rotateRoot({
    signatures: [await token(s.rootKey.kid), await token(replacement.kid)],
  });
  await expect(
    s.sdk.rotateRoot({ signatures: [await token(s.rootKey.kid), await token(replacement.kid)] }),
  ).rejects.toThrow();
});
it('does not count duplicate signatures toward a threshold', async () => {
  const s = setup();
  const other = s.ring.generate('license');
  s.ring.activate(other.kid);
  s.root.release.keys.push({ kid: other.kid, jwk: other.publicJwk });
  s.root.release.threshold = 2;
  // The client clones its embedded root; construct a client with the threshold policy.
  const sdk = new SecureUpdateClient({
    root: s.root,
    product: 'editor',
    platform: 'windows-x64',
    channel: 'stable',
    store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
    now: () => new Date(now * 1000),
  });
  const e = await s.sign(s.manifest);
  await expect(
    sdk.verifyManifest({ signatures: [...e.signatures, ...e.signatures] }),
  ).rejects.toThrow();
});

it('retains rollback and clock protection across client restart', async () => {
  const s = setup();
  const e = await s.sign(s.manifest);
  await s.sdk.verifyManifest(e);
  const sdk = new SecureUpdateClient({
    root: s.root,
    product: 'editor',
    platform: 'windows-x64',
    channel: 'stable',
    store: {
      get: async (k) => s.values.get(k),
      set: async (k, v) => {
        s.values.set(k, v);
      },
      delete: async () => {},
    },
    now: () => new Date((now - 61) * 1000),
  });
  await expect(sdk.verifyManifest(e)).rejects.toThrow('clock rollback');
});
it('rejects tampered bytes and unknown manifest fields', async () => {
  const s = setup();
  const e = await s.sign(s.manifest);
  const parts = e.signatures[0]!.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...s.manifest, sequence: 3 })).toString('base64url');
  await expect(s.sdk.verifyManifest({ signatures: [parts.join('.')] })).rejects.toThrow(
    'signature threshold',
  );
  await expect(
    s.sdk.verifyManifest(await s.sign({ ...s.manifest, unexpected: true } as UpdateManifest)),
  ).rejects.toThrow('malformed');
});
it('supports release-key revocation through root rotation', async () => {
  const s = setup();
  const nextKey = s.ring.generate('license');
  s.ring.activate(nextKey.kid);
  const next = {
    ...s.root,
    version: 2,
    release: { threshold: 1, keys: [{ kid: nextKey.kid, jwk: nextKey.publicJwk }] },
  };
  await s.sdk.rotateRoot({
    signatures: [
      await signJws(
        { ...next },
        { kid: s.rootKey.kid, typ: 'trust-update-root+jws' },
        s.ring.custody,
      ),
    ],
  });
  await expect(s.sdk.verifyManifest(await s.sign(s.manifest))).rejects.toThrow(
    'signature threshold',
  );
  expect(await s.sdk.verifyManifest(await s.sign(s.manifest, nextKey.kid))).toEqual(s.manifest);
});
