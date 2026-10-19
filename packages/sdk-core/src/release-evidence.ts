import { createHash } from 'node:crypto';
import type { UpdateManifest } from './updates.ts';

// Release evidence (ADR-028): the signed manifest pins the SHA-256 of a CycloneDX SBOM and of an in-toto/SLSA
// provenance statement. These checks make that pin meaningful: the bytes match the digests, both documents
// describe THIS artifact, and the build ran on a builder the product trusts.

export const IN_TOTO_STATEMENT = 'https://in-toto.io/Statement/v1';
export const SLSA_PROVENANCE = 'https://slsa.dev/provenance/v1';
export const CYCLONEDX_VERSIONS = ['1.4', '1.5', '1.6'] as const;
export const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;

export interface EvidencePolicy {
  /** Builder identities (`runDetails.builder.id`) allowed to have produced releases. Must not be empty. */
  trustedBuilders: readonly string[];
}

export interface VerifiedEvidence {
  builderId: string;
  buildType: string;
  components: number;
}

function fail(reason: string): never {
  throw new Error(`release evidence rejected: ${reason}`);
}
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const obj = (v: unknown): Record<string, unknown> | undefined =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;

function parse(bytes: Uint8Array, what: string): Record<string, unknown> {
  if (bytes.length > MAX_EVIDENCE_BYTES) fail(`${what} too large`);
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return fail(`${what} is not JSON`);
  }
  return obj(v) ?? fail(`${what} is not an object`);
}

/** The SBOM must be CycloneDX and name the artifact by its SHA-256. */
export function checkSbom(bytes: Uint8Array, artifactSha256: string): { components: number } {
  const bom = parse(bytes, 'SBOM');
  if (bom['bomFormat'] !== 'CycloneDX') fail('SBOM is not CycloneDX');
  if (!CYCLONEDX_VERSIONS.includes(bom['specVersion'] as (typeof CYCLONEDX_VERSIONS)[number]))
    fail('unsupported CycloneDX version');
  const component = obj(obj(bom['metadata'])?.['component']);
  const hashes = component?.['hashes'];
  if (
    !Array.isArray(hashes) ||
    !hashes.some((h) => obj(h)?.['alg'] === 'SHA-256' && obj(h)?.['content'] === artifactSha256)
  )
    fail('SBOM does not describe this artifact');
  const components = bom['components'];
  if (components !== undefined && !Array.isArray(components)) fail('SBOM components malformed');
  return { components: Array.isArray(components) ? components.length : 0 };
}

/** The provenance must be an in-toto v1 statement with an SLSA v1 predicate about exactly this artifact. */
export function checkProvenance(
  bytes: Uint8Array,
  artifactSha256: string,
  policy: EvidencePolicy,
): { builderId: string; buildType: string } {
  if (!policy.trustedBuilders.length) fail('no trusted builders configured');
  const st = parse(bytes, 'provenance');
  if (st['_type'] !== IN_TOTO_STATEMENT) fail('not an in-toto v1 statement');
  if (st['predicateType'] !== SLSA_PROVENANCE) fail('not SLSA v1 provenance');
  const subject = st['subject'];
  if (!Array.isArray(subject) || subject.length !== 1) fail('provenance must name one subject');
  if (obj(obj(subject[0])?.['digest'])?.['sha256'] !== artifactSha256)
    fail('provenance is about another artifact');
  const predicate = obj(st['predicate']);
  const buildType = obj(predicate?.['buildDefinition'])?.['buildType'];
  const builderId = obj(obj(predicate?.['runDetails'])?.['builder'])?.['id'];
  if (typeof buildType !== 'string' || !buildType) fail('provenance has no build type');
  if (typeof builderId !== 'string' || !policy.trustedBuilders.includes(builderId))
    fail('untrusted builder');
  return { builderId, buildType };
}

/** All checks for one release: digests pinned by the signed manifest, then content. */
export function verifyReleaseEvidence(
  manifest: UpdateManifest,
  evidence: { sbom: Uint8Array; provenance: Uint8Array },
  policy: EvidencePolicy,
): VerifiedEvidence {
  if (sha256(evidence.sbom) !== manifest.artifact.sbom_sha256) fail('SBOM digest mismatch');
  if (sha256(evidence.provenance) !== manifest.artifact.provenance_sha256)
    fail('provenance digest mismatch');
  const { components } = checkSbom(evidence.sbom, manifest.artifact.sha256);
  const p = checkProvenance(evidence.provenance, manifest.artifact.sha256, policy);
  return { ...p, components };
}

/** Evidence lives next to the artifact on the same approved origin. */
export function evidenceUrls(artifactUrl: string): { sbom: string; provenance: string } {
  const sibling = (suffix: string) => {
    const url = new URL(artifactUrl);
    url.pathname += suffix;
    return url.href;
  };
  return { sbom: sibling('.cdx.json'), provenance: sibling('.intoto.json') };
}
