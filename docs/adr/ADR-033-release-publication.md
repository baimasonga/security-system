# ADR-033: Verified signed release publication

Warrior accepts already-signed envelopes from an authenticated operator, against an
existing product/target sequence reservation. It never signs, fetches an artifact,
or installs software. UPDATE_CATALOG_ENABLED remains opt-in. Every mutation
requires a reason, respects platform freeze, and commits immutable history and its
audit event together under the existing product lock. Signing keys stay outside
Warrior. Registered roots remain immutable in this slice.

Publication verifies the SDK protocol's signature threshold, purpose, exact product,
platform/channel, expiry, allowed artifact origin and manifest shape. The signed
sequence must equal the reservation and the current reserved counter, and exceed the latest publication for that
exact target. A newer reservation abandons older unpublished work; gaps are safe. A receipt can publish only one exact envelope. Exact retries return
that original row without another event, including after expiry; a newer feed is
never rolled back by a retry. Invalid or conflicting envelopes produce generic
errors without echoing their contents. History reads are operator-only and bounded.

Anonymous current-feed reads expose only the signed envelope for an active product,
registered target and newest published sequence. They are no-store, expiry-aware,
and never fall back to an older release. A signed paused manifest remains visible,
so SDK clients refuse staging. Withdrawal is a newly reserved, higher-sequence signed
paused release; metadata cannot be edited or deleted. Refresh also needs a higher
sequence. Root expiry stops feed delivery. Missing/expired metadata is not proof
of support, revocation or artifact availability. Clients still pin their own roots
and enforce their own persisted watermarks and evidence policies.

Before reserving for an existing product, operators can raise its target sequence
floor using trusted historical build records and a mandatory audit reason. This
is available only before the first publication for a target, must strictly raise
the counter, and is an operator attestation, not proof of a signature or a replacement for client
watermarks. It can only raise the counter, never delete receipts or alter a
published envelope. Reconcile every previously distributed channel; gaps are safe.

Migration 0028_release_publications adds append-only history linked to exact
reservations. Apply it and grants from the new image before deployment. App roles
can read/insert history, not modify/delete it; triggers protect owner mistakes too.
Old images reject newer schema; use a compatible forward build for rollback, retain
history and do not change the migration ledger. No live migration/flags/keys are
changed by local implementation. Root rotation, cohort rollout, artifact custody,
native installers and production acceptance remain separate work.
