# ADR-028: Release evidence — SBOM and provenance bound by digest

Status: accepted. Affects trust boundaries: **yes** (what clients install).

## Context

Signed update manifests (ADR-019) already pin `sbom_sha256` and `provenance_sha256`, but nothing produced or
checked those documents, so the pins proved nothing. The requirement
([architecture/09](../architecture/09-advanced-feature-requirements.md#signed-updates-and-supply-chain)): SBOM and
provenance are attached to each release and linked by digest.

## Decision

- **Formats.** SBOM: CycloneDX JSON 1.4–1.6 whose `metadata.component.hashes` contains the installer's SHA-256.
  Provenance: an in-toto v1 Statement with an SLSA v1 provenance predicate, exactly one subject whose `sha256` is
  the installer's, a `buildDefinition.buildType` and `runDetails.builder.id`; the SBOM digest is recorded as a
  byproduct and the source repository/commit as a resolved dependency.
- **Publishing.** `tools/release-evidence.ts` (run in the product's release pipeline) refuses an SBOM that does not
  name the installer, writes `<artifact>.cdx.json` and `<artifact>.intoto.json` without ever overwriting, and prints
  the manifest's `artifact` fragment (url, size, sha256, sbom_sha256, provenance_sha256) to sign with
  `tools/sign-update.ts` / the production KMS signer. Evidence is hosted next to the artifact on the same
  root-approved origin.
- **Verifying.** `SecureUpdateClient.verifyEvidence(envelope, { trustedBuilders })` re-verifies the signed manifest,
  downloads both files from the artifact's origin (no redirects, 2 MiB cap while streaming), checks both digests
  against the signed pins, then checks the content: the SBOM describes this installer; the provenance is about this
  installer and was produced by a builder in the product's own allow-list (an empty list is refused).
  `verifyReleaseEvidence` is the same check for hosts with their own transport.
- **Signing keys.** Unchanged: release metadata is signed by the update release role under the pinned root; the
  provenance itself is unsigned and gets its integrity from the signed digest. A builder-signed (e.g. Sigstore)
  attestation can be layered on later without changing the manifest.

## Consequences

- A compromised artifact host can no longer swap SBOM or provenance unnoticed, and a release built outside the
  trusted builders is rejected by clients that pass a policy.
- The platform still cannot prove the builder itself is honest; that is what the builder allow-list delegates to
  the product's CI identity.
