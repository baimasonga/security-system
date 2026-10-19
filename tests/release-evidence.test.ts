import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyRing, signJws } from '@trust/crypto';
import {
  SecureUpdateClient,
  checkProvenance,
  checkSbom,
  verifyReleaseEvidence,
  type UpdateManifest,
} from '@trust/sdk-core';
import { buildProvenance } from '../tools/release-evidence.ts';

const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');
const BUILDER = 'https://github.com/rokela/editor/.github/workflows/release.yml@refs/heads/main';
const policy = { trustedBuilders: [BUILDER] };
const installer = Buffer.from('signed installer bytes');
const sbomFor = (digest: string, extra: Record<string, unknown> = {}) =>
  Buffer.from(
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      metadata: { component: { name: 'editor', hashes: [{ alg: 'SHA-256', content: digest }] } },
      components: [{ name: 'zlib', version: '1.3.1' }],
      ...extra,
    }),
  );
const provenanceFor = (digest: string, builder = BUILDER) =>
  Buffer.from(
    JSON.stringify(
      buildProvenance({
        artifactName: 'editor-setup.exe',
        artifactSha256: digest,
        sbomSha256: 'c'.repeat(64),
        builderId: builder,
        buildType: 'https://rokela.example/build/windows-installer/v1',
        source: { uri: 'git+https://github.com/rokela/editor', commit: 'a'.repeat(40) },
        startedOn: new Date('2026-10-01T00:00:00Z'),
        finishedOn: new Date('2026-10-01T00:10:00Z'),
      }),
    ),
  );
const manifestFor = (sbom: Buffer, provenance: Buffer): UpdateManifest => ({
  schema: 1,
  product: 'editor',
  platform: 'windows-x64',
  channel: 'stable',
  sequence: 1,
  version: '1.0',
  minimum_sequence: 1,
  issued_at: 1_800_000_000 - 1,
  expires: 1_800_000_000 + 100,
  paused: false,
  artifact: {
    url: 'https://updates.example/editor-setup.exe',
    size: installer.length,
    sha256: sha(installer),
    sbom_sha256: sha(sbom),
    provenance_sha256: sha(provenance),
  },
});

describe('release evidence', () => {
  it('accepts an SBOM and provenance bound to the artifact and produced by a trusted builder', () => {
    const sbom = sbomFor(sha(installer));
    const prov = provenanceFor(sha(installer));
    expect(
      verifyReleaseEvidence(manifestFor(sbom, prov), { sbom, provenance: prov }, policy),
    ).toEqual({
      builderId: BUILDER,
      buildType: 'https://rokela.example/build/windows-installer/v1',
      components: 1,
    });
  });

  it('refuses every way the evidence can fail to prove the build', () => {
    const d = sha(installer);
    const sbom = sbomFor(d);
    const prov = provenanceFor(d);
    const m = manifestFor(sbom, prov);
    const tryWith = (s: Buffer, p: Buffer, mm = m, pol = policy) => {
      try {
        verifyReleaseEvidence(mm, { sbom: s, provenance: p }, pol);
        return 'ok';
      } catch (e) {
        return (e as Error).message.replace('release evidence rejected: ', '');
      }
    };
    expect(tryWith(sbomFor(d, { components: [{ name: 'other' }] }), prov)).toBe(
      'SBOM digest mismatch',
    );
    expect(tryWith(sbom, provenanceFor(d, 'https://evil.example/builder'))).toBe(
      'provenance digest mismatch',
    );
    // correctly pinned but about another artifact / by another builder / wrong format
    const otherSbom = sbomFor('e'.repeat(64));
    expect(tryWith(otherSbom, prov, manifestFor(otherSbom, prov))).toBe(
      'SBOM does not describe this artifact',
    );
    const otherProv = provenanceFor('e'.repeat(64));
    expect(tryWith(sbom, otherProv, manifestFor(sbom, otherProv))).toBe(
      'provenance is about another artifact',
    );
    const evilProv = provenanceFor(d, 'https://evil.example/builder');
    expect(tryWith(sbom, evilProv, manifestFor(sbom, evilProv))).toBe('untrusted builder');
    expect(tryWith(sbom, prov, m, { trustedBuilders: [] })).toBe('no trusted builders configured');
    const spdx = Buffer.from(JSON.stringify({ spdxVersion: 'SPDX-2.3' }));
    expect(tryWith(spdx, prov, manifestFor(spdx, prov))).toBe('SBOM is not CycloneDX');
    const oldSlsa = Buffer.from(
      JSON.stringify({
        ...JSON.parse(prov.toString()),
        predicateType: 'https://slsa.dev/provenance/v0.2',
      }),
    );
    expect(tryWith(sbom, oldSlsa, manifestFor(sbom, oldSlsa))).toBe('not SLSA v1 provenance');
    const notJson = Buffer.from('<xml/>');
    expect(tryWith(notJson, prov, manifestFor(notJson, prov))).toBe('SBOM is not JSON');
    expect(() => checkSbom(Buffer.alloc(3 * 1024 * 1024, 32), d)).toThrow(/too large/);
    expect(() => checkProvenance(prov, d, { trustedBuilders: ['https://other.example'] })).toThrow(
      /untrusted builder/,
    );
  });

  it('the client downloads evidence next to the artifact and verifies it against the signed manifest', async () => {
    const d = sha(installer);
    const sbom = sbomFor(d);
    const prov = provenanceFor(d);
    const m = manifestFor(sbom, prov);
    const ring = new KeyRing();
    const r = ring.generate('license');
    const k = ring.generate('license');
    ring.activate(r.kid);
    ring.activate(k.kid);
    const envelope = {
      signatures: [
        await signJws({ ...m }, { kid: k.kid, typ: 'trust-update-manifest+jws' }, ring.custody),
      ],
    };
    const served: Record<string, Buffer> = {
      'https://updates.example/editor-setup.exe.cdx.json': sbom,
      'https://updates.example/editor-setup.exe.intoto.json': prov,
    };
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (u) => {
      const body = served[String(u)];
      return body ? new Response(body) : new Response('missing', { status: 404 });
    });
    const client = () =>
      new SecureUpdateClient({
        root: {
          schema: 1,
          version: 1,
          expires: 1_800_000_000 + 100,
          root: { threshold: 1, keys: [{ kid: r.kid, jwk: r.publicJwk }] },
          release: { threshold: 1, keys: [{ kid: k.kid, jwk: k.publicJwk }] },
          artifact_origins: ['https://updates.example'],
        },
        product: 'editor',
        platform: 'windows-x64',
        channel: 'stable',
        store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
        now: () => new Date(1_800_000_000 * 1000),
        fetch: fetcher,
      });
    const ok = await client().verifyEvidence(envelope, policy);
    expect(ok.builderId).toBe(BUILDER);
    expect(fetcher.mock.calls.every((c) => c[1]?.redirect === 'error')).toBe(true);
    // a swapped SBOM on the server is caught by the signed digest
    served['https://updates.example/editor-setup.exe.cdx.json'] = sbomFor(d, { components: [] });
    await expect(client().verifyEvidence(envelope, policy)).rejects.toThrow(/SBOM digest mismatch/);
    // oversized evidence is cut off while streaming
    served['https://updates.example/editor-setup.exe.cdx.json'] = Buffer.alloc(3 * 1024 * 1024, 32);
    await expect(client().verifyEvidence(envelope, policy)).rejects.toThrow(/evidence size/);
  });

  it('the release tool writes immutable evidence and prints the manifest fragment', () => {
    const dir = mkdtempSync(join(tmpdir(), 'release-evidence-'));
    const artifact = join(dir, 'editor-setup.exe');
    writeFileSync(artifact, installer);
    writeFileSync(join(dir, 'editor.cdx.json'), sbomFor(sha(installer)));
    const run = () =>
      execFileSync(
        process.execPath,
        [
          'tools/release-evidence.ts',
          '--artifact',
          artifact,
          '--sbom',
          join(dir, 'editor.cdx.json'),
          '--builder-id',
          BUILDER,
          '--build-type',
          'https://rokela.example/build/windows-installer/v1',
          '--url',
          'https://updates.example/editor-setup.exe',
        ],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      );
    const fragment = JSON.parse(run());
    expect(fragment).toMatchObject({ size: installer.length, sha256: sha(installer) });
    const prov = readFileSync(`${artifact}.intoto.json`);
    expect(fragment.provenance_sha256).toBe(sha(prov));
    expect(fragment.sbom_sha256).toBe(sha(readFileSync(`${artifact}.cdx.json`)));
    expect(checkProvenance(prov, sha(installer), policy).builderId).toBe(BUILDER);
    expect(run).toThrow(); // never overwrites published evidence
    // an SBOM that does not name this installer is refused before anything is written
    const other = join(dir, 'other.exe');
    writeFileSync(other, Buffer.from('different'));
    expect(() =>
      execFileSync(
        process.execPath,
        [
          'tools/release-evidence.ts',
          '--artifact',
          other,
          '--sbom',
          join(dir, 'editor.cdx.json'),
          '--builder-id',
          BUILDER,
          '--build-type',
          'https://rokela.example/x',
          '--url',
          'https://updates.example/other.exe',
        ],
        { stdio: 'pipe' },
      ),
    ).toThrow();
  });
});
