import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { expect, it, vi } from 'vitest';
import { KeyRing, signJws } from '@trust/crypto';
import {
  ProductUpdateManager,
  type ProductUpdateRegistration,
  type SecureStore,
  type UpdateManifest,
  type UpdateRoot,
} from '../src/index.ts';

const now = 1_800_000_000;
const clock = () => new Date(now * 1000);
const hash = (bytes: string) => createHash('sha256').update(bytes).digest('hex');
function fixture(product: string) {
  const ring = new KeyRing();
  const r = ring.generate('license'),
    k = ring.generate('license');
  ring.activate(r.kid);
  ring.activate(k.kid);
  const artifact = `installer for ${product}`;
  const url = `https://updates.example/${product}/artifact`;
  const sbom = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: {
      component: {
        type: 'application',
        name: product,
        hashes: [{ alg: 'SHA-256', content: hash(artifact) }],
      },
    },
    components: [],
  });
  const provenance = JSON.stringify({
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: product, digest: { sha256: hash(artifact) } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: { buildType: 'test-build' },
      runDetails: { builder: { id: 'https://builder.example/approved' } },
    },
  });
  const manifest: UpdateManifest = {
    schema: 1,
    product,
    platform: 'windows-x64',
    channel: 'stable',
    sequence: 5,
    version: '2.0',
    minimum_sequence: 3,
    issued_at: now - 1,
    expires: now + 300,
    paused: false,
    artifact: {
      url,
      size: Buffer.byteLength(artifact),
      sha256: hash(artifact),
      sbom_sha256: hash(sbom),
      provenance_sha256: hash(provenance),
    },
  };
  const root: UpdateRoot = {
    schema: 1,
    version: 1,
    expires: now + 3600,
    root: { threshold: 1, keys: [{ kid: r.kid, jwk: r.publicJwk }] },
    release: { threshold: 1, keys: [{ kid: k.kid, jwk: k.publicJwk }] },
    artifact_origins: ['https://updates.example'],
  };
  const registration: ProductUpdateRegistration = {
    product,
    root,
    evidence: { trustedBuilders: ['https://builder.example/approved'] },
    targets: [
      {
        platform: 'windows-x64',
        channel: 'stable',
        feedUrl: `https://updates.example/${product}/stable.json`,
        installedSequence: 2,
      },
    ],
  };
  const sign = async (m = manifest, kid = k.kid) => ({
    signatures: [await signJws({ ...m }, { kid, typ: 'trust-update-manifest+jws' }, ring.custody)],
  });
  return { registration, manifest, ring, r, k, sign, artifact, sbom, provenance };
}
function storeFixture() {
  const values = new Map<string, string>();
  const store: SecureStore = {
    get: async (key) => {
      const value = values.get(key);
      await setImmediate();
      return value;
    },
    set: async (key, value) => {
      values.set(key, value);
    },
    delete: async (key) => {
      values.delete(key);
    },
  };
  return { values, store };
}
function target(product: string, channel = 'stable', platform = 'windows-x64') {
  return { product, channel, platform };
}
it('checks two independently signed products with their own installed sequence and roots', async () => {
  const a = fixture('business'),
    b = fixture('pdf'),
    s = storeFixture();
  b.registration.targets[0]!.installedSequence = 5;
  const bodies = new Map([
    [a.registration.targets[0]!.feedUrl, await a.sign()],
    [b.registration.targets[0]!.feedUrl, await b.sign()],
  ]);
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(async (url) => new Response(JSON.stringify(bodies.get(String(url)))));
  const manager = new ProductUpdateManager({
    products: [a.registration, b.registration],
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  const results = await manager.checkAll();
  expect(results).toMatchObject([
    {
      target: target('business'),
      state: 'checked',
      update: { support: 'update_required', release: 'available', installedSequence: 2 },
    },
    {
      target: target('pdf'),
      state: 'checked',
      update: { support: 'supported', release: 'current', installedSequence: 5 },
    },
  ]);
  expect([...s.values.keys()].sort()).toEqual(['updates_v1_business', 'updates_v1_pdf']);
  for (const [, options] of fetcher.mock.calls) expect(options?.redirect).toBe('error');
});
it('preserves both channel checkpoints across concurrent managers and restart', async () => {
  const a = fixture('business'),
    s = storeFixture();
  a.registration.targets.push({
    ...a.registration.targets[0]!,
    channel: 'beta',
    feedUrl: 'https://updates.example/business/beta.json',
  });
  const first = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  const second = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  await Promise.all([
    first.verifyManifest(target('business'), await a.sign()),
    second.verifyManifest(
      target('business', 'beta'),
      await a.sign({ ...a.manifest, channel: 'beta', sequence: 8 }),
    ),
  ]);
  const saved = JSON.parse(s.values.get('updates_v1_business')!);
  expect(saved.targets['windows-x64/stable'].sequence).toBe(5);
  expect(saved.targets['windows-x64/beta'].sequence).toBe(8);
  const restarted = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  await expect(
    restarted.verifyManifest(target('business'), await a.sign({ ...a.manifest, sequence: 4 })),
  ).rejects.toThrow('rollback');
  await expect(
    restarted.verifyManifest(
      target('business', 'beta'),
      await a.sign({ ...a.manifest, channel: 'beta', sequence: 7 }),
    ),
  ).rejects.toThrow('rollback');
});
it.each(['product', 'platform', 'channel'] as const)(
  'rejects a signed wrong %s target without changing state',
  async (field) => {
    const a = fixture('business'),
      s = storeFixture();
    const manager = new ProductUpdateManager({
      products: [a.registration],
      store: s.store,
      now: clock,
    });
    await expect(
      manager.verifyManifest(target('business'), await a.sign({ ...a.manifest, [field]: 'other' })),
    ).rejects.toThrow('binding');
    expect(s.values.size).toBe(0);
  },
);
it('rejects a different product signing authority even with the expected product label', async () => {
  const a = fixture('business'),
    b = fixture('pdf'),
    s = storeFixture();
  const manager = new ProductUpdateManager({
    products: [a.registration, b.registration],
    store: s.store,
    now: clock,
  });
  await expect(
    manager.verifyManifest(target('business'), await b.sign(a.manifest)),
  ).rejects.toThrow('signature');
  expect(s.values.size).toBe(0);
  await manager.verifyManifest(target('business'), await a.sign());
});
it('shares root rotation across all channels without changing another product', async () => {
  const a = fixture('business'),
    b = fixture('pdf'),
    s = storeFixture();
  a.registration.targets.push({ ...a.registration.targets[0]!, channel: 'beta' });
  const manager = new ProductUpdateManager({
    products: [a.registration, b.registration],
    store: s.store,
    now: clock,
  });
  const nextRootKey = a.ring.generate('license'),
    nextReleaseKey = a.ring.generate('license');
  a.ring.activate(nextRootKey.kid);
  a.ring.activate(nextReleaseKey.kid);
  const next = {
    ...a.registration.root,
    version: 2,
    root: { threshold: 1, keys: [{ kid: nextRootKey.kid, jwk: nextRootKey.publicJwk }] },
    release: { threshold: 1, keys: [{ kid: nextReleaseKey.kid, jwk: nextReleaseKey.publicJwk }] },
  };
  const signatures = await Promise.all(
    [a.r.kid, nextRootKey.kid].map((kid) =>
      signJws({ ...next }, { kid, typ: 'trust-update-root+jws' }, a.ring.custody),
    ),
  );
  await manager.rotateRoot('business', { signatures });
  await expect(manager.verifyManifest(target('business'), await a.sign())).rejects.toThrow(
    'signature',
  );
  await manager.verifyManifest(
    target('business', 'beta'),
    await a.sign({ ...a.manifest, channel: 'beta' }, nextReleaseKey.kid),
  );
  await manager.verifyManifest(target('pdf'), await b.sign());
  expect(JSON.parse(s.values.get('updates_v1_business')!).root.version).toBe(2);
  expect(JSON.parse(s.values.get('updates_v1_pdf')!).root.version).toBe(1);
});
it('snapshots configuration, target lists and queued envelopes', async () => {
  const a = fixture('business'),
    s = storeFixture();
  const manager = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  a.registration.product = 'altered';
  a.registration.root.release.keys = [];
  a.registration.targets[0]!.channel = 'wrong';
  manager.listTargets()[0]!.product = 'changed';
  const envelope = await a.sign();
  const pending = manager.verifyManifest(target('business'), envelope);
  envelope.signatures.length = 0;
  expect((await pending).product).toBe('business');
  expect(manager.listTargets()).toEqual([target('business')]);
});
it('returns unavailable on one failed product while another remains checked, without error details', async () => {
  const a = fixture('business'),
    b = fixture('pdf'),
    s = storeFixture();
  const envelope = await b.sign();
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (String(url).includes('/business/'))
      throw new Error('private query credential should not escape');
    return new Response(JSON.stringify(envelope));
  });
  const manager = new ProductUpdateManager({
    products: [a.registration, b.registration],
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  const results = await manager.checkAll();
  expect(results[0]).toEqual({ target: target('business'), state: 'unavailable' });
  expect(results[1]).toMatchObject({ state: 'checked', update: { manifest: { product: 'pdf' } } });
  expect(JSON.stringify(results)).not.toContain('credential');
  expect(s.values.has('updates_v1_business')).toBe(false);
  await manager.verifyManifest(target('business'), await a.sign());
});
it('stages only the selected product with its registered evidence policy', async () => {
  const a = fixture('business'),
    b = fixture('pdf'),
    s = storeFixture();
  const contents = new Map([
    [a.manifest.artifact.url, a.artifact],
    [a.manifest.artifact.url + '.cdx.json', a.sbom],
    [a.manifest.artifact.url + '.intoto.json', a.provenance],
  ]);
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(
      async (url) =>
        new Response(contents.get(String(url)), { status: contents.has(String(url)) ? 200 : 404 }),
    );
  const manager = new ProductUpdateManager({
    products: [a.registration, b.registration],
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  const directory = await mkdtemp(join(tmpdir(), 'product-update-'));
  try {
    const staged = await manager.stageArtifact(target('business'), await a.sign(), directory);
    expect(await readFile(staged.path, 'utf8')).toBe(a.artifact);
    expect(fetcher.mock.calls.map(([u]) => String(u))).toEqual([
      a.manifest.artifact.url + '.cdx.json',
      a.manifest.artifact.url + '.intoto.json',
      a.manifest.artifact.url,
    ]);
    expect(s.values.has('updates_v1_pdf')).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
it('refuses staging when builder evidence is untrusted, without downloading the installer', async () => {
  const a = fixture('business'),
    s = storeFixture();
  a.registration.evidence.trustedBuilders = ['https://another-builder.example'];
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(
      async (url) =>
        new Response(
          String(url) === a.manifest.artifact.url
            ? a.artifact
            : String(url).endsWith('.cdx.json')
              ? a.sbom
              : a.provenance,
        ),
    );
  const manager = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  // Caller changes cannot weaken the registered policy after construction.
  a.registration.evidence.trustedBuilders = ['https://builder.example/approved'];
  const directory = await mkdtemp(join(tmpdir(), 'product-update-'));
  try {
    await expect(
      manager.stageArtifact(target('business'), await a.sign(), directory),
    ).rejects.toThrow('builder');
    expect(await readdir(directory)).toEqual([]);
    expect(fetcher.mock.calls.some(([u]) => String(u) === a.manifest.artifact.url)).toBe(false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
it.each([
  'http://updates.example/feed',
  'https://unknown.example/feed',
  'https://user:password@updates.example/feed',
  'https://updates.example/feed#secret',
])('rejects untrusted feed configuration %s', (feedUrl) => {
  const a = fixture('business'),
    s = storeFixture();
  a.registration.targets[0]!.feedUrl = feedUrl;
  expect(() => new ProductUpdateManager({ products: [a.registration], store: s.store })).toThrow();
  expect(s.values.size).toBe(0);
});
it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
  'rejects invalid installed sequence %s',
  (installedSequence) => {
    const a = fixture('business'),
      s = storeFixture();
    a.registration.targets[0]!.installedSequence = installedSequence;
    expect(
      () => new ProductUpdateManager({ products: [a.registration], store: s.store }),
    ).toThrow();
  },
);
it('rejects duplicate products, duplicate targets, absent builder policy and unknown targets', () => {
  const a = fixture('business'),
    s = storeFixture();
  expect(
    () => new ProductUpdateManager({ products: [a.registration, a.registration], store: s.store }),
  ).toThrow();
  a.registration.targets.push({ ...a.registration.targets[0]! });
  expect(() => new ProductUpdateManager({ products: [a.registration], store: s.store })).toThrow();
  a.registration.targets.pop();
  const manager = new ProductUpdateManager({ products: [a.registration], store: s.store });
  expect(() => manager.check(target('unknown'))).toThrow('not registered');
  expect(() => manager.rotateRoot('unknown', { signatures: [] })).toThrow('not registered');
  a.registration.evidence.trustedBuilders = [];
  expect(() => new ProductUpdateManager({ products: [a.registration], store: s.store })).toThrow();
});

it('bounds batch network concurrency to four targets while keeping registration order', async () => {
  const products = Array.from({ length: 8 }, (_, i) => fixture(`product-${i}`));
  const s = storeFixture();
  const bodies = new Map(
    await Promise.all(
      products.map(async (p) => [p.registration.targets[0]!.feedUrl, await p.sign()] as const),
    ),
  );
  let active = 0,
    peak = 0;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    active++;
    peak = Math.max(peak, active);
    await setImmediate();
    active--;
    return new Response(JSON.stringify(bodies.get(String(url))));
  });
  const manager = new ProductUpdateManager({
    products: products.map((p) => p.registration),
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  const results = await manager.checkAll();
  expect(peak).toBe(4);
  expect(results.map((r) => r.target.product)).toEqual(products.map((p) => p.registration.product));
  expect(results.every((r) => r.state === 'checked')).toBe(true);
});
it.each([5, 6])(
  'never stages current or older releases for installed build %s',
  async (installedSequence) => {
    const a = fixture('business'),
      s = storeFixture();
    a.registration.targets[0]!.installedSequence = installedSequence;
    const fetcher = vi.fn<typeof fetch>();
    const manager = new ProductUpdateManager({
      products: [a.registration],
      store: s.store,
      now: clock,
      fetch: fetcher,
    });
    await expect(
      manager.stageArtifact(target('business'), await a.sign(), tmpdir()),
    ).rejects.toThrow('not available');
    expect(fetcher).not.toHaveBeenCalled();
  },
);
it('preserves pause and expiry rejection without artifact download', async () => {
  const a = fixture('business'),
    s = storeFixture();
  const fetcher = vi.fn<typeof fetch>();
  const manager = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
    fetch: fetcher,
  });
  await expect(
    manager.stageArtifact(
      target('business'),
      await a.sign({ ...a.manifest, paused: true }),
      tmpdir(),
    ),
  ).rejects.toThrow('not available');
  await expect(
    manager.verifyManifest(target('business'), await a.sign({ ...a.manifest, expires: now })),
  ).rejects.toThrow('freshness');
  expect(fetcher).not.toHaveBeenCalled();
});
it('rejects lost root-rotation signatures and keeps the existing root usable', async () => {
  const a = fixture('business'),
    s = storeFixture();
  const manager = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  await expect(manager.rotateRoot('business', { signatures: [] })).rejects.toThrow();
  await manager.verifyManifest(target('business'), await a.sign());
  expect(JSON.parse(s.values.get('updates_v1_business')!).root.version).toBe(1);
});
it('does not lose a rotated root when a concurrent manager verifies another channel', async () => {
  const a = fixture('business'),
    s = storeFixture();
  a.registration.targets.push({ ...a.registration.targets[0]!, channel: 'beta' });
  const first = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  const second = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  const replacement = a.ring.generate('license');
  a.ring.activate(replacement.kid);
  const next = {
    ...a.registration.root,
    version: 2,
    root: { threshold: 1, keys: [{ kid: replacement.kid, jwk: replacement.publicJwk }] },
  };
  const envelope = {
    signatures: await Promise.all(
      [a.r.kid, replacement.kid].map((kid) =>
        signJws({ ...next }, { kid, typ: 'trust-update-root+jws' }, a.ring.custody),
      ),
    ),
  };
  const beta = await a.sign({ ...a.manifest, channel: 'beta' });
  await Promise.all([
    first.rotateRoot('business', envelope),
    second.verifyManifest(target('business', 'beta'), beta),
  ]);
  const saved = JSON.parse(s.values.get('updates_v1_business')!);
  expect(saved.root.version).toBe(2);
  expect(saved.targets['windows-x64/beta'].sequence).toBe(5);
});

it('keeps platform rollback histories independent within the same product', async () => {
  const a = fixture('business'),
    s = storeFixture();
  a.registration.targets.push({ ...a.registration.targets[0]!, platform: 'linux-x64' });
  const manager = new ProductUpdateManager({
    products: [a.registration],
    store: s.store,
    now: clock,
  });
  await Promise.all([
    manager.verifyManifest(target('business'), await a.sign()),
    manager.verifyManifest(
      target('business', 'stable', 'linux-x64'),
      await a.sign({ ...a.manifest, platform: 'linux-x64', sequence: 20 }),
    ),
  ]);
  // A higher Linux sequence must not prevent a legitimate Windows release.
  await manager.verifyManifest(target('business'), await a.sign({ ...a.manifest, sequence: 6 }));
  const saved = JSON.parse(s.values.get('updates_v1_business')!);
  expect(saved.targets['windows-x64/stable'].sequence).toBe(6);
  expect(saved.targets['linux-x64/stable'].sequence).toBe(20);
  await expect(
    manager.verifyManifest(
      target('business', 'stable', 'linux-x64'),
      await a.sign({ ...a.manifest, platform: 'linux-x64', sequence: 19 }),
    ),
  ).rejects.toThrow('rollback');
});
