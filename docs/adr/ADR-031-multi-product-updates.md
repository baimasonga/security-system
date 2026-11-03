# ADR-031: Multi-product update coordination

## Scope and authority

Rokela Bai Bureh Warrior serves independently configured products, not just Business
Admin. The existing signed update protocol (ADR-019/028) remains the authority.
`ProductUpdateManager` is a reusable Node/Electron SDK coordinator over that verifier,
not a signer, installation engine, release database or authorization service.

The host supplies trusted product roots, exact platform/channel targets, feed URLs,
installed build sequences and allowed builders. Configuration is snapshotted at
construction. No feed can register a product, change its target or supply builder
policy. A product can have several targets; duplicate product/target registrations,
invalid sequences and non-HTTPS or non-root-approved initial feed origins fail before
network or checkpoint access. Products may deliberately trust the same authority;
otherwise their independent roots prevent cross-product signing authority.

## State and concurrency

Existing `updates_v1_<product>` state is preserved for compatibility. Root rotation
is shared across the product's platforms/channels; each target retains its own
sequence/digest watermark. All coordinator calls for a product are serialized using
a process-local lock keyed by the exact SecureStore object and product, including
calls through separate manager instances. Other products progress independently.
A failed operation releases its lock. Concurrent checks cannot overwrite another
channel's watermark or undo root rotation.

This does not lock across processes, separate SecureStore wrappers, duplicate SDK
module instances, or standalone SecureUpdateClient callers. Hosts must serialize
those paths using a single trusted broker or an OS-level lock. Protected durable
storage is still required; deleting/replacing that storage defeats checkpoint
history. Product codes and embedded trust policy are host authority, not secrets.

## Checks and staging

Checks return verified support/update status against trusted installed build metadata.
A batch checks at most four targets at a time and retains per-target unavailable
results without leaking exceptions, private URLs or credentials into the result.
Unavailable is never supported/current. A failed product does not suppress another
product's results. Batch checks never download artifacts or execute an installer.

Staging is an explicit target-scoped operation and requires a newer, unpaused release
than the registered installed sequence. Current/ahead builds cannot stage a downgrade.
It always uses the registered
builder policy, existing evidence verification, artifact hash/size checks, freshness,
pause and rollback protections. Inputs are snapshotted before queued work. No
installation or product-data restriction occurs. Existing roots must approve each
feed origin after rotation, even if an old registered URL then becomes unusable.

## Acceptance and remaining work

Tests use real Ed25519 signatures and checkpoint storage with controlled HTTPS
responses: two products, multiple channels/platforms, wrong target/signing authority,
restarts, concurrent managers, failure recovery, root rotation, bounded batch checks,
configuration mutation and mandatory evidence policy. Negative-control mutation
checks must detect lost serialization, target binding bypass and evidence bypass.

Operator release publishing/history/withdrawal APIs and UI, production KMS/HSM
custody and hosting, C#/.NET protocol parity and Windows atomic installation/recovery
are subsequent implementation slices. This SDK change does not claim those features
or alter production configuration. Existing licensing and customer data remain intact.
