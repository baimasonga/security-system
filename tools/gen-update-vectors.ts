// Public-only cross-language update metadata fixtures; ephemeral signing keys are discarded.
import { KeyRing, signJws, b64urlEncode } from '@trust/crypto';
const ring = new KeyRing();
const owner = ring.generate('license');
const first = ring.generate('license');
const second = ring.generate('license');
const now = 1772323200;
const root = {
  schema: 1,
  version: 1,
  expires: now + 30 * 86400,
  root: { threshold: 1, keys: [{ kid: owner.kid, jwk: owner.publicJwk }] },
  release: { threshold: 1, keys: [first, second].map((k) => ({ kid: k.kid, jwk: k.publicJwk })) },
  artifact_origins: ['https://updates.example'],
};
const manifest = {
  schema: 1,
  product: 'sierra-business',
  platform: 'windows-x64',
  channel: 'stable',
  sequence: 2,
  version: '0.34.0',
  minimum_sequence: 1,
  issued_at: now,
  expires: now + 3600,
  paused: false,
  artifact: {
    url: 'https://updates.example/setup.exe',
    size: 1234,
    sha256: 'a'.repeat(64),
    sbom_sha256: 'b'.repeat(64),
    provenance_sha256: 'c'.repeat(64),
  },
};
const sign = (payload: object, kid = first.kid, typ = 'trust-update-manifest+jws') =>
  signJws(payload as Record<string, unknown>, { kid, typ }, ring.custody);
const token = await sign(manifest);
const other = await sign(manifest, second.kid);
const cases: Array<Record<string, unknown>> = [];
const add = (name: string, signatures: string[], accepted: boolean, over: object = {}) =>
  cases.push({
    name,
    root,
    envelope: { signatures },
    now,
    product: manifest.product,
    platform: manifest.platform,
    channel: manifest.channel,
    accepted,
    ...over,
  });
add('valid metadata', [token], true);
add('valid pause', [await sign({ ...manifest, paused: true })], true);
add('two independent release signatures', [token, other], true, {
  root: { ...root, release: { ...root.release, threshold: 2 } },
});
add('duplicate signatures do not satisfy threshold', [token, token], false, {
  root: { ...root, release: { ...root.release, threshold: 2 } },
});
add('root key cannot sign a release', [await sign(manifest, owner.kid)], false);
add(
  'conflicting signed payloads',
  [token, await sign({ ...manifest, sequence: 3 }, second.kid)],
  false,
);
add(
  'unknown signature does not veto valid threshold',
  [await sign(manifest, owner.kid), token],
  true,
);
add('wrong purpose', [await sign(manifest, first.kid, 'lease+jws')], false);
const [h, p, s] = token.split('.') as [string, string, string];
add(
  'tampered payload',
  [`${h}.${b64urlEncode(JSON.stringify({ ...manifest, sequence: 99 }))}.${s}`],
  false,
);
add('tampered signature', [`${h}.${p}.${b64urlEncode(Buffer.alloc(64))}`], false);
add('wrong product', [token], false, { product: 'other-product' });
add('wrong platform', [token], false, { platform: 'linux-x64' });
add('wrong channel', [token], false, { channel: 'beta' });
add('expired manifest at exact boundary', [token], false, { now: manifest.expires });
add('future issue beyond tolerance', [token], false, { now: now - 61 });
add('issue at tolerance boundary', [token], true, { now: now - 60 });
add('expired pinned root', [token], false, { root: { ...root, expires: now } });
add('invalid lifetime', [await sign({ ...manifest, expires: now + 604801 })], false);
add('minimum above sequence', [await sign({ ...manifest, minimum_sequence: 3 })], false);
add('unsafe sequence', [await sign({ ...manifest, sequence: 9007199254740992 })], false);
add(
  'fractional size',
  [await sign({ ...manifest, artifact: { ...manifest.artifact, size: 1.5 } })],
  false,
);
add('unknown manifest member', [await sign({ ...manifest, extra: true })], false);
for (const url of [
  'http://updates.example/setup.exe',
  'https://evil.example/setup.exe',
  'https://user:pass@updates.example/setup.exe',
  'https://updates.example/setup.exe#fragment',
])
  add(
    `untrusted artifact URL ${cases.length}`,
    [await sign({ ...manifest, artifact: { ...manifest.artifact, url } })],
    false,
  );
add(
  'bad digest',
  [await sign({ ...manifest, artifact: { ...manifest.artifact, sha256: 'A'.repeat(64) } })],
  false,
);
add('private JWK field', [token], false, {
  root: {
    ...root,
    release: {
      threshold: 1,
      keys: [{ kid: first.kid, jwk: { ...first.publicJwk, d: 'not-private-material' } }],
    },
  },
});
add('shared root and release key', [token], false, { root: { ...root, root: root.release } });
add('duplicate public key under new ID', [token], false, {
  root: {
    ...root,
    release: {
      threshold: 1,
      keys: [root.release.keys[0], { ...root.release.keys[0], kid: 'duplicate' }],
    },
  },
});
console.log(JSON.stringify({ schema: 1, cases }, null, 2));
