# ADR-034: Native .NET update metadata verification

Status: implemented metadata and checkpoint-transition primitives; not an installed update client.

Provide a reusable .NET 10 library under `sdks/dotnet`, independent of Business
Admin, to inspect the same release envelopes as the Node verifier. The trusted
host supplies an independently distributed public root, exact product/platform/
channel and current time. Reject malformed or oversized input, unknown fields,
private or duplicate public keys, shared root/release keys, insufficient distinct
signatures, conflicting authenticated payloads, incorrect signature purpose,
wrong targets, expired roots/releases, excessive/future validity and unapproved
artifact origins. NSec Ed25519 verifies original compact-JWS bytes. No private
key is supplied to the verifier. Errors contain fixed reasons, not input contents.

This first slice is deliberately stateless: `VerifiedUpdateMetadata` means only
that metadata passed these checks at the supplied time. It is **not** permission
to install, a supported-build verdict, evidence verification or proof of artifact
availability. There is no network, installer execution, persistent watermark,
protected storage or root-rotation API. It must not replace Business Admin's
running update flow or be advertised as a complete secure updater.

Shared public fixtures are consumed by both Node and .NET tests; generation uses
ephemeral signing keys and exports no private material. The native parser also
rejects duplicate JSON members and control characters in URLs; those ambiguous
inputs are outside its accepted subset even if a legacy JavaScript parser can
interpret them. Public roots and signing keys stay separate from license roots.

The checkpoint transition primitive now binds host-supplied previous state to the
exact pinned-root JSON bytes and product/platform/channel. It rejects sequence
rollback and same-sequence changes using SHA-256 of the canonical authenticated
payload (including issue time, expiry, pause and evidence hashes). Signature-envelope
ordering and extra unknown signatures do not change this payload identity. Clock
rollback beyond 60 seconds is rejected; tolerated backward movement never lowers
the last-seen watermark. Bad state fails closed rather than silently becoming first
use. A rejected transition leaves the caller's immutable state unchanged.

This primitive does not persist state. A trusted host must serialize the entire
load/verify/save operation across processes, protect and atomically commit state
before acting on metadata, and distinguish first use from deleted/corrupt state.
Passing null again resets checkpoint history and is only valid for explicitly
authorized first use. Exact-root binding deliberately rejects root replacement,
including JSON formatting changes; migration/root rotation needs its own protocol.
This is conditional rollback detection with trustworthy retained state, not durable
rollback protection, rollback resistance against a local administrator, an installed
version verdict or permission to install. No existing product update flow changes.

Windows storage slice: `WindowsUpdateCheckpointStore` protects state with DPAPI
CurrentUser and purpose/path-specific entropy. A persistent lock file is opened
with exclusive sharing for the entire load/verify/save transition; lock contention
has a bounded wait and cancellation. Saves flush a new sibling file before an
atomic replacement. Metadata is returned only after successful persistence.
Explicit initialization requires no existing state; ordinary verification never
initializes missing/corrupt state. Storage exceptions expose no file contents.
Use a dedicated trusted local directory, not a network/synchronized share. The
host must retain this path across upgrades and never retry failures as first use.
DPAPI protects confidentiality/integrity at rest, not deletion or rollback by the
same Windows user or administrator. Whole-state rollback remains outside this
threat boundary. No license, customer document or installed updater is modified.

Bounded transport and evidence-gated staging are now supplied by ADR-035. Next,
integrate each Windows product independently and implement
publisher verification, installation/recovery and interrupted-install acceptance.
Existing customer documents and license state are unaffected by this library.

## Stateless rotation verification — 3 November 2026

`VerifyRootRotation` now verifies sequential replacement roots against both current
and replacement root thresholds using the protocol purpose `trust-update-root+jws`.
It reuses metadata signature parsing, validates strict public-only root policy,
requires current and new root freshness, distinct signatures per role and identical
authenticated root payloads across roles. It returns root JSON without mutating the
verifier or any checkpoint. Fixed errors never echo envelope contents.

The stateless API alone does not close the durable root migration gap. A host cannot replace the
root and reinitialize its Windows store: root-bound checkpoints must be migrated
without resetting sequence, payload digest or time history. Use the atomic protected
root/checkpoint transition described below under the existing cross-process lock before product
integration. Bounded transport, evidence staging and installation/recovery remain
later steps. Shared public fixtures contain no private signing keys.

## Atomic protected trust migration — acceptance contract

The next slice adds a versioned trust state containing the exact trusted root JSON
and its target-bound checkpoint. Rotation must authenticate the sequential root
under both authorities, preserve sequence and payload history, and advance (never
lower) the observed clock. Metadata checks always use the root loaded from that
protected state. Rotate/verify/load/save share one exclusive process-independent
lock and one flushed atomic replacement; no metadata or new root is returned until
persistence succeeds. Invalid, absent, legacy or corrupt established state never
triggers initialization. Explicit first use is separate. Replayed rotations fail.
No network transport, artifact/evidence staging, installer execution, production
keys or existing Business Admin integration changes are authorized by this slice.

Acceptance covers immutable pure transitions, root/checkpoint binding, target,
clock, sequence and equivocation refusals; Windows DPAPI restart, copied/corrupt
state rejection, save failure, cancellation, and separate-process contention.
Old checkpoint-only storage remains supported by its existing API; it is not
silently upgraded into a rotating trust store. The new host integration must choose
a stable dedicated path and explicitly provision its independently pinned root.

Implementation: `UpdateTrustVerifier` supplies the pure state transitions and
`WindowsUpdateTrustStore` commits the root and checkpoint as one versioned DPAPI
record. Both storage APIs reuse one internal file transaction implementation, so
lock, path binding, cancellation and failed-replacement semantics remain shared.
Encrypted input is bounded to 512 KiB; clear serialization is bounded before
protection. Exact old root hashes are replaced only after dual-authority validation.
Clock tolerance never lowers the recorded time. The storage schema rejects legacy
checkpoint objects and unknown members; there is no automatic format migration.
Rotation returns only after commit; failures never expose a newly trusted root.
There is no live schema/API change, new deployment configuration, or installer.
