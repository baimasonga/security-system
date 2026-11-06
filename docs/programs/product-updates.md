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

The verifier/stager layer supports Node/Electron and native .NET (see ADR-035). It does not install software, create
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

## Release console — third slice, 3 November 2026

The existing Operator console includes Product releases with public-root and target
registration, historical floor attestation, retry-preserving sequence reservations,
externally signed publication/pause, bounded history and anonymous no-store feed reads.
Registry rows distinguish reserved counters from latest historical publications.
Errors clear prior results, unavailable history stays unknown, and leaving the
account/view prevents late responses from replacing the current page. Signing,
artifact fetching, client trust roots and native installation remain outside the UI.
No production flag, signing key, schema or account state is changed by this slice.

Real Chromium acceptance covers an API commit followed by a lost reservation
response, exact UUID retry with no sequence consumption, invalid-signature refusal,
verified signed pause publication, history/current reads, expired-feed semantics,
mobile containment, feature-disabled refusal and customer exclusion. Existing MFA
QR/confirmation/recovery/sign-in browser acceptance is verified separately; that
is not proof of any owner's production enrollment.

Verification: repository checks passed 1,198 tests (three intentionally skipped);
all 29 real-browser workflows passed after preserving Operations overview as the
default operator panel. The focused release browser suite separately verifies
failed-history-refresh cleanup. Formatting, types and boundaries pass; the existing
mobile-analytics regular-expression lint warning is unchanged. This UI-only slice
adds no database or authorization behavior; existing signed publication checks remain
server-enforced. Production acceptance and owner MFA status are not inferred.

## Next implementation slices

### Integrated operator access — 3 November 2026

The integration branch brings the previously separate coordination, registry,
signed-publication and release-console branches together with native metadata and
Windows checkpoint storage. Operators have a direct **Software updates** navigation
entry as well as **Operator console → Product releases**. Customers have neither.
The page reads an operator-only, no-store deployment-availability endpoint; failed
refreshes clear previous status. Availability describes the server feature flag,
not an installed client, signing custody or successful artifact verification.

Production rollout requires migrations `0027_release_registry` and
`0028_release_publications`, owner-side grants and app-role verification from this
image. Existing Railway startup ordering must continue to stop on migration/grant
failure. Enable `UPDATE_CATALOG_ENABLED=true` only after deployment acceptance.
Without that flag, the screen remains visible and explicitly reports that release
management is not enabled. No signing private key is accepted or provisioned, and
no desktop installer gains automatic updates merely by deploying the portal.

Local integration checks: 1,229 repository tests passed (three skipped); the full
initial browser integration passed 34 workflows and the final release/overview
subset passed five workflows. Owner/app-role tests for the final status endpoint
passed 18 tests. Removing its operator guard was caught by assertions; original
source was restored. A 30-device, five-seat licensing herd yielded exactly five
successes and 25 device-limit refusals, with zero deadlocks/retries/exhaustion,
matching the earlier registry/publication correctness baseline. This is not a
throughput improvement claim. Full clean PostgreSQL acceptance and GitHub release
checks must complete before rollout; live configuration remains separate evidence.

1. Review the release-console slice, then define rollout-cohort semantics before
   adding staged percentage rollout; absence of a release is never proof of support.
2. Reusable C#/.NET verifier and atomic rotating trust state are implemented locally
   (see the acceptance entries below), including bounded evidence-gated staging.
   Next are native installation and
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

## Native rotation verification — 3 November 2026

The .NET metadata verifier now exposes stateless dual-threshold root verification,
with shared Node/.NET public fixtures for valid rotation and negative authorization,
version, duplicate-signature, purpose, expiry, role-separation and conflict cases.
This is not an installed updater or durable root migration. Next: atomically migrate
the protected root and checkpoint without lowering sequence/time history, then add
bounded evidence-gated transport and native installer recovery. Existing Business
Admin updates and live signing/configuration are unchanged. Verification results
are recorded after running the applicable suites; no production acceptance is inferred.

Local verification for this slice: `npm run check` passed 1,242 tests with three
intentional skips; formatting, type checks and boundaries passed. The existing
mobile-analytics regex lint warning remains (zero lint errors). .NET tests passed
51 with five native Windows storage tests skipped on Linux. The 13 rotation vectors
are also exercised against Node; existing metadata vectors remain compatible.
Deliberately reducing either authority threshold or removing cross-authority root
agreement caused assertion failures; controls were restored and the complete .NET
suite passed again. No database schema, API route or production setting changed.

## Atomic native trust state — 6 November 2026

Added a versioned combined root/checkpoint record with dual-authority sequential
rotation, unchanged release sequence/payload history and monotonic clock history.
The new Windows trust store reuses the existing DPAPI and exclusive cross-process
file transaction and commits the whole record atomically before returning success.
Existing checkpoint-only callers retain their API. No installed product, signing
key, network feed or production state is changed; legacy files are not silently
converted. Pure transitions and native Windows failure/concurrency tests accompany
the implementation. Verification results are recorded after the relevant checks;
Linux skips are not evidence of native DPAPI acceptance.

Local verification: `npm run check` passed 1,242 tests with three intentional
skips; formatting, types and boundaries passed with the existing mobile-regex
lint warning. The complete .NET suite passed 55 tests; ten native Windows tests
were intentionally skipped on Linux. Four isolated negative controls (root binding,
release sequence, clock watermark and established-state validation) each caused
assertion failures, and the restored suite passed. Native Windows CI and delivery
results remain separate acceptance evidence. No database or live product changes
were made.

Next: bounded transport and evidence verification/staging in .NET, then integrate
Business Admin and a second Windows product independently. Native installation,
interrupted-update recovery and production custody/hosting remain later work.

## Native evidence-gated staging — 6 November 2026

Implemented `ReleaseEvidenceVerifier`, bounded production HTTPS transport and
`UpdateArtifactStager` on top of the concrete Windows trust store. Signed evidence
digests, exact installer binding, approved builders, streaming size/hash checks,
response/body deadlines and final protected-state verification gate every result.
Root/sequence observation commits before network activity; failed fetches do not
forget it. Concurrent rotation/newer metadata, expired evidence, failed final saves
and cancellation discard partial staging. Success returns a disposable private file,
never installation authority. No installed product, production key or live provider
configuration changes. The previous atomic-trust PR #48 passed all GitHub checks
and was merged before starting this increment.

Tests include signer-endorsed but semantically wrong evidence, mutable builder
policy, unknown-length oversized streams, corrupted/truncated artifacts, clock and
trust changes during download, cancellation and checkpoint failures. Real local
HTTPS verifies CA/name validation, redirect refusal and stalled-body deadlines;
native Windows tests cover protected commits, restrictive ACLs and the read lease.
Verification and delivery evidence are recorded after running the applicable checks.

Local verification: `npm run check` passed 1,242 tests with three intentional skips;
formatting, types and boundaries passed with the existing mobile-regex warning.
The complete .NET suite passed 98 tests with twelve native Windows cases skipped
on Linux. Nine isolated staging mutations were caught and the restored suite passed.
Real HTTPS acceptance uses an ephemeral local CA without changing system trust;
the production transport retains normal TLS verification. Native Windows CI remains
separate from these Linux results. No schema, production setting, key or installed
product was changed by this slice.

Next: platform publisher verification and native installation/recovery adapters,
then independently integrate Business Admin and a second Windows product. Production
signing/hosting, interrupted-install drills and live acceptance remain required.
