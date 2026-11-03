# Update registry and release sequence reservations

This is the central update catalog (ADR-032/033), not a software download
or installer service. It applies independently to Business Admin and future
products. Registry management requires a platform operator session. The current signed feed
is anonymous; all catalog routes are disabled by default. Customer licenses never grant registry access.

## Deployment

1. Prepare the new source/image and apply `0027_release_registry` using the existing
   owner migration connection, then run `npm run db:grants` and `npm run db:check`
   with the application connection. The API start command is not a substitute for
   deployment preparation. The startup guard requires this migration even if the
   feature flag is false.
2. Verify in staging before setting `UPDATE_CATALOG_ENABLED=true`. Keep signing
   private keys outside Warrior. No new paid service or provider is needed.
3. Keep the flag false to leave these routes unavailable. It does not remove
   reservations or make the previous application image schema-compatible. After
   migration, use a compatible forward build if a release must be rolled back.

## Operator workflow

Use the existing product ID from the licensing catalog. All mutations require a
nonblank `reason` (3–500 characters) and respect platform freeze.

| Method and path (under `/v1/admin/products/{productId}`) | Behavior                                                                                                                                 |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /update-registry`                                  | Body: `root`, `reason`. Register one valid public version-one UpdateRoot with separate root/release keys and future expiry. Returns 201. |
| `GET /update-registry`                                   | Return the registered public root and at most 32 targets. No arbitrary query fields.                                                     |
| `POST /update-registry/targets`                          | Body: `platform`, `channel`, `reason`. Add an exact target such as `windows-x64` / `stable`, starting its counter at zero. Returns 201.  |
| `POST /update-registry/reservations`                     | Body: `platform`, `channel`, UUID `request_id`, `reason`. Atomically reserve the next sequence; returns 200 with the receipt.            |

Persist the request ID before requesting a reservation. If the connection fails,
retry the **same request ID and target**: the original receipt is returned without
consuming another sequence. Reusing the ID for another target is a conflict.
Different products may use the same request ID independently. Abandoned numbers
are never recycled. A reservation does not mean that a release was published.

The receipt includes `product_id`, `request_id`, `platform`, `channel`, `sequence`
and `created_at`. Registry targets use `reserved_sequence` in the wire response.
The registry root remains protocol-shaped; it contains only public material.

Register the root from the trusted signing process, not from an unverified feed.
Registration does not change installed clients' embedded trust roots or establish
proof of signing-key custody. Already-released products need their historical
sequence floor reconciled before publication is implemented; do not treat a new
catalog counter as authority to downgrade an installed client.

## Failure and evidence semantics

- Missing or inactive products are not registrable. Missing registry/target returns 404. Root replacement, duplicate target, capacity or request-ID conflicts return 409. Expired roots and a backwards server clock reject new work. Exact receipt
  retries remain readable after expiry (but writes still respect platform freeze).
- Root/target creation and reservations are audited atomically with their changes.
  Audit events contain product/target identifiers, root digest or sequence, not
  signing keys or artifact contents. An audit failure must leave no reservation.
- PostgreSQL serializes per product across processes and stores immutable receipt
  history. Memory mode is development-only; its state does not survive a process
  restart. The production profile continues requiring PostgreSQL.
- No purge endpoint exists for receipts. Operators must plan storage retention;
  deleting history to recover storage can cause unsafe sequence reuse.

Signed root rotation and native Windows installation/recovery remain separate work.
The operator release console below uses these existing APIs.

## Signed publication and current feeds (ADR-033)

Migration `0028_release_publications` and app-role grants are required before the
new image starts, even with the flag off. No private signing key belongs in Warrior.

1. Reconcile every historical target before reserving: `POST /sequence-floor`
   with `platform`, `channel`, `sequence` and mandatory `reason`. Use trusted build
   records. This attestation must strictly raise the counter and is available only
   before the first publication for that target; it is not signature proof. Equal
   floor retries return 409; read the registry to reconcile an uncertain response.
2. Reserve, sign externally with the registered release authorities, then
   `POST /releases` with `platform`, `channel`, reservation UUID `request_id`,
   `envelope: {signatures: [...]}` and `reason`. All strict protocol checks apply.
   Only the latest reserved sequence can publish; a later reservation abandons older
   unpublished work. Finish a publication before reserving another for that target.
3. Retry the exact envelope and request ID after uncertain responses. A published
   receipt cannot change; exact retries remain readable after expiry but never
   replace a newer feed. History and its audit event commit atomically.
4. `GET /releases?platform=windows-x64&channel=stable&limit=20&before=42`
   is operator-only immutable history; limit is 1–50, before is exclusive.
5. `GET /v1/updates/{productId}/current?platform=windows-x64&channel=stable`
   is anonymous, flag-gated, `Cache-Control: no-store` and returns the original
   signed envelope, not a re-signed or snake-cased payload. The feed origin must be
   allowed in clients' pinned root for SDK fetches. No root is automatically installed.

Missing/expired newest metadata or expired authority returns 404, never an older
release. A signed pause stays visible: reserve a higher sequence and publish a
signed `paused: true` manifest to withdraw distribution. To resume or refresh
expiry, reserve/sign/publish a higher sequence. Existing offline metadata does not
vanish from clients; their signature/expiry/checkpoint rules remain authoritative.

The registry proves metadata signature acceptance, not artifact availability,
SBOM/provenance verification, trusted builds or successful installation. No server
artifact fetch or installer is implemented by this endpoint.

## Operator release console

In **Operator console → Product releases**, choose a release operation. The console
uses the existing operator APIs and does not sign, fetch or install artifacts.
It supports public root and target registration, historical floor attestation,
sequence reservation, externally signed publication (including a signed pause),
bounded immutable history and a no-store anonymous current-feed read.

Enter the existing licensing product ID and exact platform/channel. Registry reads
show each target's reserved counter separately from the latest publication and its
historical signed state. Historical release/pause labels do not establish current
availability, artifact verification or installed-client support. A history failure
is shown as unknown, never as zero releases. A missing current feed can mean expiry,
absence, a disabled catalog or a service failure; it is not evidence of revocation.

Generate and save a reservation UUID in trusted release records before submitting.
The UI retains all form inputs after success or failure, but does not persist them
across navigation/reloads. After an uncertain response, use the same UUID and target;
a publication retry must also preserve its exact signed envelope. Reserving another
sequence abandons older unpublished work. Paste only public roots and signed
metadata, never private signing keys. Mutation confirmation, required audit reasons,
freeze enforcement and signature validation remain authoritative on the server.
Withdraw through a higher-sequence externally signed pause, not a delete/edit action.

The console adds no new feature flag or migration. The registry/publication schema,
grants and UPDATE_CATALOG_ENABLED prerequisites above still apply. Percentage
rollouts, root rotation, native C# staging/installation and recovery remain separate.
