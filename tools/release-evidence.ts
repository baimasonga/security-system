// Release evidence (ADR-028): binds an installer, its CycloneDX SBOM and an in-toto/SLSA v1 provenance statement
// by digest, and prints the `artifact` fragment of the update manifest.
//
// Usage (in the product's release pipeline, after building `editor-setup.exe` and its SBOM):
//   node tools/release-evidence.ts --artifact dist/editor-setup.exe --sbom dist/editor.cdx.json \
//     --builder-id https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/heads/main \
//     --build-type https://rokela.example/build/windows-installer/v1 \
//     --source-uri git+https://github.com/OWNER/REPO --source-commit <40-hex> --url https://updates.example/...
// Writes <artifact>.cdx.json and <artifact>.intoto.json (never overwriting), prints the manifest fragment.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IN_TOTO_STATEMENT, SLSA_PROVENANCE, checkSbom } from '@trust/sdk-core';

export interface ProvenanceInput {
  artifactName: string;
  artifactSha256: string;
  sbomSha256: string;
  builderId: string;
  buildType: string;
  source?: { uri: string; commit: string } | undefined;
  startedOn: Date;
  finishedOn: Date;
}

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

export function buildProvenance(p: ProvenanceInput): Record<string, unknown> {
  if (!/^[a-f0-9]{64}$/.test(p.artifactSha256) || !/^[a-f0-9]{64}$/.test(p.sbomSha256))
    throw new Error('digests must be lowercase SHA-256 hex');
  for (const u of [p.builderId, p.buildType]) {
    if (!/^https:\/\/\S+$/.test(u)) throw new Error('builder id and build type must be https URIs');
  }
  if (p.source && !/^[a-f0-9]{40}$/.test(p.source.commit))
    throw new Error('source commit must be a 40-character hex id');
  return {
    _type: IN_TOTO_STATEMENT,
    subject: [{ name: p.artifactName, digest: { sha256: p.artifactSha256 } }],
    predicateType: SLSA_PROVENANCE,
    predicate: {
      buildDefinition: {
        buildType: p.buildType,
        externalParameters: p.source ? { source: p.source.uri } : {},
        resolvedDependencies: p.source
          ? [{ uri: p.source.uri, digest: { gitCommit: p.source.commit } }]
          : [],
      },
      runDetails: {
        builder: { id: p.builderId },
        metadata: { startedOn: p.startedOn.toISOString(), finishedOn: p.finishedOn.toISOString() },
        byproducts: [{ name: 'sbom.cdx.json', digest: { sha256: p.sbomSha256 } }],
      },
    },
  };
}

function arg(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function main(argv: string[]) {
  const artifact = arg(argv, 'artifact');
  const sbomPath = arg(argv, 'sbom');
  const builderId = arg(argv, 'builder-id');
  const buildType = arg(argv, 'build-type');
  const url = arg(argv, 'url');
  if (!artifact || !sbomPath || !builderId || !buildType || !url)
    throw new Error(
      'usage: node tools/release-evidence.ts --artifact FILE --sbom FILE --builder-id URI --build-type URI --url ARTIFACT_URL [--source-uri URI --source-commit SHA]',
    );
  const started = new Date();
  // Paths come from the release operator's own command line.
  const bytes = await readFile(artifact);
  const sbom = await readFile(sbomPath);
  const artifactSha256 = sha256(bytes);
  checkSbom(sbom, artifactSha256); // the SBOM must name this exact installer
  const sourceUri = arg(argv, 'source-uri');
  const sourceCommit = arg(argv, 'source-commit');
  const provenance = Buffer.from(
    JSON.stringify(
      buildProvenance({
        artifactName: basename(artifact),
        artifactSha256,
        sbomSha256: sha256(sbom),
        builderId,
        buildType,
        source: sourceUri && sourceCommit ? { uri: sourceUri, commit: sourceCommit } : undefined,
        startedOn: started,
        finishedOn: new Date(),
      }),
      null,
      2,
    ) + '\n',
  );
  // Published evidence is immutable: never overwrite.
  await writeFile(`${artifact}.cdx.json`, sbom, { flag: 'wx' });
  await writeFile(`${artifact}.intoto.json`, provenance, { flag: 'wx' });
  console.log(
    JSON.stringify(
      {
        url,
        size: bytes.length,
        sha256: artifactSha256,
        sbom_sha256: sha256(sbom),
        provenance_sha256: sha256(provenance),
      },
      null,
      2,
    ),
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main(process.argv.slice(2)).catch((e: unknown) => {
    console.error(`release evidence failed: ${(e as Error).message}`);
    process.exitCode = 1;
  });
