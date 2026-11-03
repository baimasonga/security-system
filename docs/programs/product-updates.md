# Shared product update implementation

Rokela Bai Bureh Warrior is shared infrastructure for current and future products.
Business Admin is an integration, not the owner of the update protocol. Do not infer
live acceptance from source tests or replace installed products' trust roots remotely.

## Implemented foundation

- Signed per-product/platform/channel metadata, sequential threshold root rotation,
  rollback/freeze checks, support-floor assessment and bounded artifact staging.
- Signed digest bindings for SBOM and provenance, with an approved-builder policy.
- ADR-031 multi-product SDK coordination, trusted registration snapshots, per-product
  process-local serialization, bounded independent checks and mandatory evidence for
  explicit staging. Existing single-product checkpoint keys remain compatible.

This layer is Node/Electron only. It does not install software, create signing keys,
write a server release catalog, publish files or configure a real product automatically.

## Next implementation slices

1. Central release catalog: product-scoped targets and trust-root registration,
   authenticated operator publication with reason/audit, immutable release history,
   monotonic sequence reservation, verified signed metadata and current-feed reads.
   Serve existing signed envelopes without a server-side signing key. Define how
   expiry/refresh and higher-sequence signed pause/withdrawal interact with clients.
2. Release console using that API, explicit publish/withdraw state and status for
   every product/platform/channel. Define rollout-cohort semantics before adding
   staged percentage rollout; absence of a release is never proof of support.
3. Reusable C#/.NET verifier/stager with shared protocol test vectors, protected
   state and cross-process serialization, followed by native installation and
   recovery adapters. Integrate Business Admin and a second product independently.
4. Production signing custody and immutable hosting, platform publisher signatures,
   compromised-key recovery, interrupted-install drills and live acceptance.

## ADR-031 verification record

Focused tests exercise real signatures, two products, concurrent manager instances,
channel checkpoints, root rotation, restarts, mutation of caller configuration,
untrusted builder rejection, bounded batch checks, stale/wrong-target metadata,
paused releases and refusal to stage current/older installed sequences. Verification
results and any environment limits belong in the delivery report; this document
does not assert production deployment or Windows acceptance.
