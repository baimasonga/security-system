# Rokela .NET update verification and staging

`Rokela.Updates` targets .NET 10. It verifies public update metadata with NSec
Ed25519 and supplies bounded evidence-gated Windows staging; it never runs an installer. See
[ADR-034](../../docs/adr/ADR-034-dotnet-update-metadata.md) for the current boundary.

```csharp
using Rokela.Updates;

var verifier = new UpdateMetadataVerifier(independentlyPinnedRootJson);
var metadata = verifier.Verify(envelopeJson, "sierra-business", "windows-x64",
    "stable", DateTimeOffset.UtcNow);
// Authenticated metadata only: do not install or claim rollback protection.
```

`UpdateCheckpointVerifier.Verify` additionally accepts a host-protected
`UpdateCheckpoint` and returns metadata plus the next immutable checkpoint. It
detects older sequence numbers, conflicting signed payloads at the same sequence,
and clock rollback beyond 60 seconds. It keeps the highest observed time even
inside that tolerance. State is bound to the exact root JSON bytes and target.

This is a pure transition, **not persistent rollback protection**. Hosts must
serialize load/verify/save across processes and atomically save protected state
before using the result. Missing or corrupt established state must fail closed;
`null` means explicitly authorized first use, not automatic recovery.

On Windows, `WindowsUpdateCheckpointStore` supplies DPAPI CurrentUser protection,
an exclusive file lock across the load/verify/save transaction, bounded lock waits,
cancellation, and flushed atomic replacement. Give it a stable absolute path in a
dedicated trusted local directory retained across upgrades. `InitializeAsync` is
for explicit first use only; use `VerifyAndCommitAsync` on every subsequent call.
Missing/corrupt established state is an error. Never catch that error and call
initialization automatically. Only a successfully committed transition returns
metadata. Non-Windows hosts throw rather than silently writing plaintext.

Keep the original pinned root JSON bytes stable. State cannot be copied to a new
path, shared between Windows users, or moved to another root/target. The persistent
`.lock` file is intentional and must not be deleted while any client is running.
Orphan `.tmp` files from a killed process are not authoritative and are never read
as state. A failed save preserves existing authoritative state where replacement
has not completed. After an ambiguous crash, reload the committed file; never
reset. DPAPI is not a defense against deletion or restoration of an older whole
checkpoint by the same Windows user/admin. Network and synchronized shares are
unsupported. This checkpoint-only API does not rotate roots. For new hosts that
need rotation, use the combined trust store below. Installer execution and product
integration are not supplied by either storage API.

Run on Linux or Windows:

```sh
dotnet test sdks/dotnet/Rokela.Updates.Tests
```

Fixtures in `docs/api/update-metadata-vectors.json` are also checked by the Node
SDK. Regenerate them only alongside protocol changes with
`node tools/gen-update-vectors.ts > docs/api/update-metadata-vectors.json`.
The generator outputs public keys and signed fixtures only. No deployment,
production keys or Business Admin update settings change in this slice.

## Root rotation verification

`UpdateMetadataVerifier.VerifyRootRotation(envelopeJson, now)` authenticates the
next root with distinct signatures satisfying **both** current and replacement
root-role thresholds, requires the next sequential version and unexpired roots,
and returns validated root JSON. Release keys cannot authorize root changes.
Both authorities must authenticate the same complete root, including origins and
release policy. Public shared vectors exercise the same decisions in Node and .NET.

This is a stateless verification primitive. It does not update the verifier,
change installed trust, persist a root, or migrate an existing Windows checkpoint.
Do not construct a fresh checkpoint or reinitialize Windows storage after rotation:
that would discard rollback history. No production signing keys, installed products
or customer/license data are changed by this stateless API.

## Atomic Windows trust store

`WindowsUpdateTrustStore` stores the trusted root JSON **and** checkpoint in one
versioned DPAPI CurrentUser record. It shares the checkpoint store's exclusive
cross-process lock, bounded waits/cancellation, flushed temporary-file write and
atomic replacement. Use a dedicated stable local path; this API deliberately
rejects an existing checkpoint-only file rather than silently converting it.

```csharp
var trust = new WindowsUpdateTrustStore(stableAbsoluteTrustStatePath);
// Explicit provisioning only, after independently obtaining the initial root:
await trust.InitializeAsync(initialRootJson, firstReleaseEnvelope,
    "sierra-business", "windows-x64", "stable", DateTimeOffset.UtcNow);
// Subsequent launches load their root from protected state, not an old build pin:
var metadata = await trust.VerifyAndCommitAsync(releaseEnvelope,
    "sierra-business", "windows-x64", "stable", DateTimeOffset.UtcNow);
// Each rotation must be sequential and signed by both root authorities:
await trust.RotateRootAndCommitAsync(rotationEnvelope,
    "sierra-business", "windows-x64", "stable", DateTimeOffset.UtcNow);
```

Rotation changes only the root binding and highest observed time. Sequence and
authenticated payload digest survive unchanged, so a new signing authority cannot
replay an older release or change an existing sequence. Verification and rotation
operate under the same lock; after restart, the persisted root is authoritative.
Replayed/skipped rotations, wrong targets, expired roots, clock rollback and corrupt
state fail without resetting history. A failed replacement returns no success and
preserves the previous authoritative file. Uncommitted orphan temporary files are
never read. Missing established state is an error: **never automatically retry it
as initialization**. Back up/configure host state according to the deployment's
threat model; DPAPI does not stop whole-file rollback/deletion by the same user or
an administrator. Network/synchronized directories remain unsupported.

`UpdateTrustVerifier` exposes equivalent pure immutable transitions for testing or
other integrity-protected host storage. Passing caller-created state to it is not
proof of trust, and its result must be committed atomically before use. Metadata
authentication still does not authorize installation. Use the bounded downloader
below for evidence/staging; native installation and recovery remain separate work.

Native Windows tests cover restart, failed replacement, corrupt/copied/legacy state,
concurrent rotations and separate-process lock/cancellation. They are skipped on
Linux rather than substituting a plaintext or mocked DPAPI implementation.

## Bounded evidence-gated staging

```csharp
using var stager = new UpdateArtifactStager(trust, "sierra-business", "windows-x64",
    "stable", trustedLocalStagingDirectory,
    new[] { "https://build.example/approved" }, installedSequence: trustedInstalledSequence);
using var artifact = await stager.StageAsync(signedReleaseEnvelope, cancellationToken);
// artifact.Path is a verified temporary file, not permission to execute it.
// A future host installation adapter must verify publisher signatures and provide recovery.
```

The builder identity above is illustrative; configure actual approved builders
independently of downloaded data. The public constructor uses Windows DPAPI state,
system TLS verification, no automatic redirects/cookies/credentials and identity
encoding. Both evidence files (artifact URL plus `.cdx.json` / `.intoto.json` on
the same origin, retaining its query) are verified before installer bytes are read.
Signed digests bind the exact bytes; CycloneDX and in-toto/SLSA semantics bind them
to the installer and approved builder. This is **signer-endorsed evidence**, not
independent proof of the build environment. Unknown document fields are allowed;
duplicate JSON properties, invalid UTF-8 and oversized documents are refused.

Metadata checkpoints commit before network activity and are reverified/committed
against current trust after the flushed download. Failed downloads retain the
observed release watermark. Concurrent newer releases or incompatible rotations,
expiry, rollback, bad evidence, cancellation and final-save failures refuse the
result and remove partial staging. Networking never holds the trust-state lock.

Evidence is limited to 2 MiB per document and 30 seconds per request. Artifact
downloads default to 256 MiB and 120 seconds; the host may explicitly configure
`maximumBytes` and `requestTimeout` (at most ten minutes), based on its product.
The deadline includes streaming body reads, not just response headers. Signed and
actual artifact lengths/hashes must match exactly. The staging root must already
exist and be a trusted local directory without reparse-point/symlink ancestors.
Child directories restrict access to the current Windows user (0700 in portable
test hosts); the artifact keeps a read-sharing lease until disposed. Dispose the
result after use to close/delete it. Cleanup failures are surfaced for host action.

The SDK does not fetch update feeds, choose products, auto-initialize trust, install
software or create production keys. It does not modify license/customer documents.
See [ADR-035](../../docs/adr/ADR-035-dotnet-evidence-staging.md).

## Windows publisher verification

```csharp
var publisher = new WindowsPublisherVerifier(approvedPublisherCertificateSha256Pins);
var signedBy = publisher.Verify(artifact); // Keep artifact alive and undisposed.
// Evidence of Windows signature trust + exact publisher pin, not an installation grant.
```

Use SHA-256 of the leaf certificate's DER bytes, for example
`certificate.GetCertHashString(HashAlgorithmName.SHA256)`. The Windows certificate
store's ordinary `Thumbprint` is SHA-1 and is **not** this pin. Configure approved
pins independently of downloaded metadata and certificate subject names. Policy is
copied, and multiple pins allow an explicitly configured publisher rollover.

While holding the staged read lease, this gate rechecks full-file length/hash,
strict embedded PE signature layout, Windows `WinVerifyTrust` with revocation checks,
the actual verified signer's certificate pin and a SHA-256/384/512 signature digest.
It uses System32 trust APIs, closes native trust state and never unlocks or executes
the file. A concurrent result disposal waits for verification. The synchronous native
call can consult Windows revocation/network policy: keep verification/disposal off
the UI thread. There is no offline-ignore-revocation option.

Support currently covers PE executables/DLLs with one revision-2 PKCS#7 table at EOF
(maximum 4 MiB), canonical SignedData and zero alignment padding. Unsigned files,
unhashed trailing data, malformed tables and nonzero PKCS#7 padding fail. MSI,
PowerShell scripts and alternate signature containers need separate adapters.
Certificate subject text is informational. Windows trust alone does not satisfy the
pin, and a pin alone never overrides a Windows trust refusal.

The host must still recheck current release trust before any eventual execution,
obtain explicit installation confirmation, and provide a product-specific installer
and data/recovery adapter. The existing Business Admin Inno setup overwrites files
in place; these checks do not turn it into an atomic installer. No update is installed
by this SDK. See [ADR-036](../../docs/adr/ADR-036-windows-publisher-verification.md).
