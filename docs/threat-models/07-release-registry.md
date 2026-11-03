# Release registry: first-slice threat model

Related: ADR-019/028/031 update verification; [ADR-032](../adr/ADR-032-release-registry.md).

## Assets and trust

Protect initial public signing authorities, product/target identity, never-reused
sequence numbers, immutable reservation receipts and their audit trail. Catalog
operators are trusted to choose the initial authority; clients independently pin
their own roots. Registry success is not signing-key custody, artifact verification,
release publication or successful installation. No signing private key is accepted.

## Boundaries and controls

| Threat                                                             | Control and residual limit                                                                                                                                                                                                           |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Customer or anonymous caller chooses a product's signing authority | Every route uses current platform-operator authorization and the optional existing operator MFA policy; customer licenses are irrelevant. Source flag defaults off.                                                                  |
| Private key, invalid threshold or unapproved root replacement      | Strict existing SDK root/JWK parser, version-one/unexpired initial root, separate root/release key roles, one registration only. Registration does not itself prove possession of corresponding private keys.                        |
| Parallel builds reserve the same sequence                          | Product-scoped PostgreSQL transaction advisory lock, bounded target state, unique receipt tuple, safe-integer ceiling. Memory mode uses a serialized snapshot; no production durability claim for it.                                |
| Retry consumes another number or rebinds an existing request       | UUID lookup scoped to product, exact platform/channel match, immutable receipt history. Gaps from abandoned builds are retained.                                                                                                     |
| Database or audit failure leaves a usable but unaudited receipt    | Counter, immutable receipt and audit event use the same database transaction; retryable callbacks have no network/signing/provider side effects. Tests inject an audit-write failure after receipt statements.                       |
| Expired authority or backwards clock authorizes new work           | Root expiry and latest registry timestamp checked inside mutation; old receipt retries remain readable. Platform freeze blocks writes.                                                                                               |
| Root or sequence reset through ordinary SQL privileges             | App owns nothing; receipt grants are SELECT/INSERT only. Triggers reject receipt mutation, identity replacement, disappearing targets and decreasing counters. Database owners and compromised schema administrators remain trusted. |
| Unbounded unauthenticated input or SSRF                            | Operator-only endpoints, 32 KiB mutation body limit, at most 32 target entries, bounded protocol key/origin arrays. No outbound requests or artifact execution in this slice.                                                        |

Receipts have no purge path. Operator-authorized sustained writes can grow history;
owners must budget storage and preserve sequence history during recovery. Restoring
an old database snapshot alone can rewind reservations, so reconcile the catalog
against immutable signing/release records and installed-client watermarks before
resuming publication. Future signed metadata must still satisfy client anti-rollback
and key-rotation checks; a registry record cannot bypass them.

The release publication API, feed authority/expiry, sequence-floor import, root
rotation and operator release console are subsequent work, not implemented controls.
