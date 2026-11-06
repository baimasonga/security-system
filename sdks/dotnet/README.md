# Rokela .NET update metadata verifier

`Rokela.Updates` targets .NET 10. It verifies public update metadata with NSec
Ed25519; it never downloads or runs an installer. See
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
integration are not supplied by either API.

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
authentication still does not authorize installation: bounded downloads, evidence
verification/staging, native installation and recovery are the next slices.

Native Windows tests cover restart, failed replacement, corrupt/copied/legacy state,
concurrent rotations and separate-process lock/cancellation. They are skipped on
Linux rather than substituting a plaintext or mocked DPAPI implementation.
