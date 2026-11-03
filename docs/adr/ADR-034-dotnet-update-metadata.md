# ADR-034: Native .NET update metadata verification

Status: implemented primitive; not an installed update client.

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

Next slices: persistent rollback/equivocation and clock checkpoints, protected
cross-process state, dual-threshold root rotation, bounded transport and evidence-
gated staging. Only then integrate each Windows product independently and implement
publisher verification, installation/recovery and interrupted-install acceptance.
Existing customer documents and license state are unaffected by this library.
