# Update registry and release sequence reservations

This is the first central update-catalog slice (ADR-032), not a software download
or installer service. It applies independently to Business Admin and future
products. All routes require a platform operator session and are disabled by
default. Customer licenses never grant registry access.

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

Next slices add signed publication tied to an actual reservation, signed root
rotation, immutable release history and expiry-aware current-feed reads. The
release console and native Windows installation/recovery remain separate work.
