# ADR-032: Operator release registry and sequence reservations

## First slice

The update catalog is shared infrastructure. A platform operator can register one
initial public root for an existing active licensing product, register up to 32 exact
platform/channel targets, and reserve a monotonically increasing sequence for a
target. The registry is disabled unless `UPDATE_CATALOG_ENABLED=true`. Every route
uses the existing operator guard and platform freeze guard on writes. No anonymous
feed or installation action exists in this slice.

An initial root must be protocol-valid, version one and unexpired. It contains only
public keys; the existing SDK root parser rejects private/unknown JWK fields,
duplicate keys and invalid threshold policies. Registration does not prove custody
of signing keys and must not replace already-installed client roots. Root rotation
will require old/new threshold signatures in a later slice; re-registration cannot
replace a root here. No server signing key, remote URL fetch or artifact ingestion
is introduced.

## Atomicity and retention

PostgreSQL takes a product-scoped transaction advisory lock before reading/changing registry state.
The lock covers registration races and all targets of that product, across server
instances. Reservations increment the target counter and append an immutable
receipt plus audit event in one retryable transaction. Memory mode serializes and
commits a cloned snapshot after audit succeeds. There is no external I/O inside
these transactions. The lock order is product advisory lock, registry state, audit chains. The hash
namespace is fixed; collisions serialize unrelated products without weakening
correctness. No UPDATE permission on the licensing product table is needed.

A caller supplies a UUID request ID, unique within a product. Exact target retries
return the original receipt without incrementing or adding an audit event. Reusing
the ID for another target is a conflict. Gaps are allowed and reserved numbers are
never recycled, including after abandoned builds. Target counters stop at the
largest JavaScript-safe integer. Receipts are retained without a purge operation;
deployment owners must budget growth. Queries are key lookups and bounded targets,
not unbounded receipt scans. Root expiry prevents new reservations but does not
erase existing receipts; an exact retry remains readable after expiry.

The app role cannot update/delete reservation receipts. A trigger additionally
rejects their mutation. Root identity/target identity are immutable through this
API. Database owners remain trusted and can alter schema or records; client root
pinning and signed metadata remain independent of catalog administrative authority.

## Deployment and limits

Apply migration `0027_release_registry` then `db:grants` from the new image with the
owner connection; check the app role before enabling the flag. All known migrations
are required by the startup guard even when the feature is off. Keep the existing
healthy deployment while preparing the new image. A previous image refuses a newer
schema, so rollback requires a compatible forward build; do not delete reservations
or edit the migration ledger to force an old image to start. No production schema,
keys, flags or services are changed as part of local implementation.

Next: verified signed publication against a reserved sequence, immutable release
history, root rotation and expiry-aware current-feed reads, then release console,
C# protocol parity and native installation/recovery. Reservation success is not
release publication, signature verification, artifact availability or installation.
