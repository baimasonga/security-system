# Signed Update Verification and Staging

`SecureUpdateClient` in `@trust/sdk-core` verifies and stages releases for Node/Electron hosts. It does not install software. See ADR-019 for the trust model. Ship an independently trusted public root with the product, separate from license signing keys. Store checkpoints using protected storage and serialize access across all application processes. The class serializes calls within one instance only.

## Public Root

A root contains `schema: 1`, increasing integer `version`, UNIX-seconds `expires`, and independent `root`/`release` roles. Each role has a `threshold` and unique Ed25519 public keys `{ kid, jwk }`. Duplicate key IDs or public key material, private JWK members, and shared root/release keys are rejected. `artifact_origins` lists exact approved HTTPS origins; these origins also host signed feeds. This is a bounded protocol, not TUF conformance.

`rotateRoot({ signatures })` accepts compact JWS tokens with purpose `trust-update-root+jws`. Every counted signature covers the identical new root; both the current root threshold and the new root threshold must approve it. Versions advance exactly one at a time. Release history survives rotation. Rotate before root expiry; recovery from an expired or lost root requires an independently trusted application/configuration release. An offline installation cannot discover a new revocation until it obtains current metadata.

## Release Feed

A signed envelope contains only `signatures`, an array of compact JWS tokens with purpose `trust-update-manifest+jws`. The release role's threshold verifies an identical manifest with these fields:

| Field                                                | Contract                                                                                                 |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `schema`                                             | `1`                                                                                                      |
| `product`, `platform`, `channel`                     | Exact configured target, such as `editor`, `windows-x64`, `stable`                                       |
| `sequence`                                           | Positive monotonic integer, independent of display version                                               |
| `version`                                            | Display label, 1–80 ASCII letters/digits/dot/underscore/hyphen                                           |
| `minimum_sequence`                                   | Nonnegative minimum supported sequence, at most this release sequence                                    |
| `issued_at`, `expires`                               | UNIX seconds; at most seven days apart; expiry enforced without grace; future issue tolerance 60 seconds |
| `paused`                                             | Prevents staging while retaining rollback watermarks                                                     |
| `artifact.url`                                       | Approved HTTPS origin, no credentials/fragment/redirects                                                 |
| `artifact.size`                                      | Exact positive byte count                                                                                |
| `artifact.sha256`                                    | SHA-256 of installer bytes                                                                               |
| `artifact.sbom_sha256`, `artifact.provenance_sha256` | Digests binding release evidence                                                                         |

Construct the client with `{ root, product, platform, channel, store }`. `checkForUpdates(feedUrl)` downloads a bounded signed feed and returns `{ envelope, manifest }` after verification. `verifyManifest(envelope)` handles feeds fetched by another trusted host transport. Lower sequences, same-sequence changed content, wrong targets, unknown/revoked keys, signature failures, stale roots/manifests, malformed fields, and clock rollback beyond 60 seconds fail closed. Exact metadata can be retried until expiry.

## Installed build status

`getUpdateStatus(envelope, installedSequence)` re-verifies the signed manifest and saves its rollback checkpoint,
then returns `{ manifest, installedSequence, support, release }`. Supply the installed sequence from trusted local
build metadata. A checkpoint records observed metadata; it does not establish what was installed. Sequence zero
is permitted for legacy unnumbered installations. Negative, fractional and unsafe integer values are rejected.

| Result field | Value             | Meaning                                                           |
| ------------ | ----------------- | ----------------------------------------------------------------- |
| `support`    | `update_required` | Installed sequence is below signed `minimum_sequence`             |
| `support`    | `supported`       | Installed sequence meets the signed minimum                       |
| `release`    | `available`       | A newer signed release is available and unpaused                  |
| `release`    | `paused`          | A newer release exists but the publisher paused staging           |
| `release`    | `current`         | Installed sequence equals the signed release sequence             |
| `release`    | `installed_ahead` | Installed build is newer than this feed; do not offer a downgrade |

Support and release action are independent: an unsupported installation can have a paused update. Display version
strings are never compared. Failed signature, freshness, binding or rollback checks reject the call; they never
become a supported/current status. Hosts should show an unavailable-check state when verification fails and preserve
customer document read/export access.

```ts
const { envelope } = await updates.checkForUpdates(feedUrl);
const status = await updates.getUpdateStatus(envelope, INSTALLED_BUILD_SEQUENCE);
if (status.release === 'available') {
  // After the user's update action; host supplies its trusted builder policy.
  const staged = await updates.stageArtifact(envelope, stagingDirectory, { trustedBuilders });
  // The host verifies platform signatures and installs atomically, then removes the staging directory.
}
```

Assessment does not download evidence/installers, run an installer, or change licensing. `supported` describes the
signed minimum only, not evidence approval or platform compatibility. Hosts retain their own operating policy.

## Artifact staging

`stageArtifact(envelope, stagingDirectory)` re-verifies before download, streams bytes into a private random directory, and verifies signed size/SHA-256 before returning `{ path, manifest }`. The default artifact limit is 256 MiB and download timeout is 120 seconds. Configure a justified `maxArtifactBytes` for larger installers. Failed/interrupted downloads remove their staging directory; the host deletes successful staging directories after use.

Pass a third argument, `stageArtifact(envelope, stagingDirectory, { trustedBuilders: ['<your CI builder id>'] })`,
to require evidence verification before the installer is downloaded or any staging directory is created. The entire
operation is serialized against root rotation and other update operations on the same instance. Invalid evidence
rejects staging. The two-argument form verifies installer integrity only; hosts using it must validate evidence
separately. Successful staging still returns `{ path, manifest }`.

The host must supply a staging directory protected by OS permissions (including Windows ACLs), re-verify bytes when crossing an installation privilege boundary, and also verify Windows Authenticode publisher identity, use evidence-gated staging or call `verifyEvidence(envelope, { trustedBuilders })` separately (ADR-028) so the pinned SBOM/provenance are downloaded, digest-checked and shown to describe this installer and a trusted builder, apply its minimum-supported-version policy, and install through a platform-safe atomic/recoverable mechanism. Merely declaring an evidence digest does not verify that a build is approved. Ordinary update failures preserve the working installation and customer documents.

## Signing and Hosting

Production release pipelines provide an independent KMS/HSM `KeyCustody` to `signJws`; do not reuse the API's license signer. Generate public metadata using the exact manifest purpose above, attach threshold signatures, and host immutable installer/evidence objects and signed feeds on a root-approved origin. Cloudflare R2 is a proposed host, not configured storage.

For development with a single release signer, the repository provides:

```sh
node tools/sign-update.ts --development-software-key root.json manifest.json output.json
```

Supply `UPDATE_SIGNING_KEY_PEM` securely in the process environment. The tool verifies its output against the public root and refuses production mode or overwriting an output file. Software signing is for development; production signing, root ceremony, storage immutability and installation/recovery drills remain deployment responsibilities.

## Release evidence (ADR-028)

Run `node tools/release-evidence.ts --artifact FILE --sbom FILE.cdx.json --builder-id URI --build-type URI --url ARTIFACT_URL [--source-uri URI --source-commit SHA]` in the release pipeline. It refuses an SBOM that does not name the installer's SHA-256, writes `<artifact>.cdx.json` and `<artifact>.intoto.json` (in-toto v1 / SLSA v1) without overwriting, and prints the manifest `artifact` fragment. Upload all three next to each other. Clients call `verifyEvidence(envelope, { trustedBuilders: ['<your CI builder id>'] })` before installing.

Evidence filenames append `.cdx.json` and `.intoto.json` to the artifact URL pathname while preserving its query
parameters. The server must permit those parameters for sibling objects; artifact-specific presigned signatures
need a different host transport. Evidence verification rechecks manifest/root expiry and clock rollback after the
last download and records completion time in the protected checkpoint. It holds the same instance lock as staging
and root rotation.
