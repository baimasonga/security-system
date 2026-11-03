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

The verifier/stager layer is Node/Electron only. It does not install software, create
signing keys, publish files or configure a real product automatically.

## Central catalog registry — first slice, 3 November 2026

- Added operator-only root registration, exact platform/channel targets and atomic
  sequence reservations behind `UPDATE_CATALOG_ENABLED` (default false).
- Root registration reuses protocol validation, accepts public keys only, requires
  separate root/release authorities and refuses replacement. Installed clients'
  trust roots are not changed by catalog registration.
- PostgreSQL serializes by product across coordinator instances. UUID retries
  preserve receipts; wrong-target retries conflict; abandoned sequences are retained.
  App-role grants and database triggers preserve receipt/registry identity and
  prevent counter rollback. Memory mode is for development only.
- Every mutation requires a reason and atomic audit event. Platform freeze blocks
  writes. Root expiry and backwards clocks block new reservations, with original
  receipts retained for exact retries. At most 32 targets are registered per product.
- Migration `0027_release_registry`, grants and application-role checks are deployment
  prerequisites even when the source flag is false. No live migration, signing key,
  product registration or feature flag was changed during implementation.
- [API and deployment guide](../api/update-registry.md),
  [ADR-032](../adr/ADR-032-release-registry.md).

Local acceptance includes concurrent reservations, independent coordinators,
process-state re-creation, audit rollback, strict public-root validation, product
isolation, target cap, expiry, backwards clocks and freeze. Four negative controls
(public-root validation, request/target binding, memory serialization and operator
authorization) were caught in an isolated source copy; original controls restored.
The deterministic memory test holds an audit commit open to expose a lost update.

Verification: `npm run check` passed (1,189 tests passed, three skipped; format,
types and boundaries passed with one pre-existing mobile-regex lint warning).
Full `npm run test:db` passed 878 tests; after adding the deterministic memory race
test, the focused registry owner/app-role/DB suites passed all 17 tests. The
Chromium MFA workflow passed (one selected test, seven intentionally unselected).
Changed-file Gitleaks scanning found no leaks. Review/delivery is a separate step;
these local results do not assert a live registry rollout.

Existing MFA enrollment was also verified through API and real Chromium: QR decode,
confirmation, one-time recovery codes, old-session revocation and a subsequent MFA
sign-in. These are synthetic local tests, not proof of the owner's live account state.

The existing licensing `herd` scenario was compared with archived baseline 2583d86
using separate local PostgreSQL 17 databases with fsync on, pool 10, 30 devices and
a five-device limit. Both produced exactly five successes, 25 limit refusals and
zero deadlocks/retries/exhausted transactions. p99 was 224.81 ms before and 175.62 ms
after; this short local smoke establishes no throughput or latency improvement.

## Next implementation slices

1. Continue central release catalog: authenticated operator publication against an
   actual reservation with reason/audit, immutable release history,
   verified signed metadata and current-feed reads. Reconcile existing products'
   historical sequence floors before publishing through a new catalog counter.
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
