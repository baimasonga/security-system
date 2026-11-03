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

## Signed publication — second slice, 3 November 2026

- Added signature-verified operator publication against the latest reserved sequence,
  immutable history with bounded cursor reads and an anonymous no-store current feed.
- Historical target floors can only advance through a reasoned, audited operator
  attestation. New reservations abandon older unpublished work; numbers are never
  recycled. Exact publication retries return their original row without another audit.
- The existing SDK verifies thresholds, purpose, root freshness, exact target binding
  and allowed artifact origins. No signing key or network fetch is added to Warrior.
- Current feeds never fall back after newest-release expiry. A higher-sequence signed
  pause is the withdrawal mechanism; refreshing or resuming needs a new sequence.
- Migration `0028_release_publications`, owner-side grants and app-role verification
  are prerequisites. The existing flag remains off by default. Production was not
  migrated or enabled by this implementation. The feed is not an installer or proof
  that artifacts/evidence are available.
- [ADR-033](../adr/ADR-033-release-publication.md) and the
  [operator API workflow](../api/update-registry.md) define the acceptance boundary.

Verification for the publication slice: `npm run check` passed (1,198 passed,
three skipped; formatting, types and boundaries passed; one pre-existing
mobile-analytics regex lint warning). Full PostgreSQL owner/app-role validation
passed 898 tests. The final stricter floor controls additionally passed all 18
focused owner/app-role tests. The real Chromium MFA enable/disable/sign-in workflow
passed one selected test; seven unrelated cases were intentionally unselected.
Three isolated negative controls (signature verification, latest-reservation floor,
expired-feed rejection) each caused assertion failures. Changed-file Gitleaks
scanning found no leaks. No live-account MFA state is inferred from these tests.

The archived c9fabbf licensing herd comparison used separate disposable PostgreSQL
17 databases, fsync on, pool 10, 30 devices and a limit of five. Both baseline and
new code produced exactly five successes, 25 limit refusals and zero deadlocks,
retries or exhausted transactions. p99 was 221.76 ms versus 222.65 ms; this short
smoke is compatibility evidence, not a performance improvement claim. Concurrent
publication tests use separate coordinator objects and persistent PostgreSQL state,
with audit failure rollback and immutable-history rejection coverage.

Delivery: draft review branch `codex/signed-release-publication`, stacked on registry
PR #41. Production flags, migrations, signing keys and installed client roots remain
unchanged. Next: release-console UI, then native C# verifier/stager parity.

## Next implementation slices

1. Release console using that API, explicit publish/withdraw state and status for
   every product/platform/channel. Define rollout-cohort semantics before adding
   staged percentage rollout; absence of a release is never proof of support.
2. Reusable C#/.NET verifier/stager with shared protocol test vectors, protected
   state and cross-process serialization, followed by native installation and
   recovery adapters. Integrate Business Admin and a second product independently.
3. Production signing custody and immutable hosting, platform publisher signatures,
   compromised-key recovery, interrupted-install drills and live acceptance.

## ADR-031 verification record

Focused tests exercise real signatures, two products, concurrent manager instances,
channel checkpoints, root rotation, restarts, mutation of caller configuration,
untrusted builder rejection, bounded batch checks, stale/wrong-target metadata,
paused releases and refusal to stage current/older installed sequences. Verification
results and any environment limits belong in the delivery report; this document
does not assert production deployment or Windows acceptance.
