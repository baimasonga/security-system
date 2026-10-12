# ADR-019: Product security integration boundaries

## Device keys

The Node SDK accepts an asynchronous host-owned device-key provider, scoped to a persistent installation ID. Existing software PEM storage remains the default for compatibility. When an explicit provider fails, the SDK fails closed rather than generating a replacement software key. Signing may be asynchronous for OS key stores and hardware services. Provider labels are not attestation evidence. The activation protocol currently requires Ed25519; hosts whose TPM/Keystore supports only P-256 must not pretend compatibility. Hardware attestation verification remains platform-specific and requires an independently validated trust chain, nonce, identity binding, and supported native host.

## Updates

Update keys and metadata have distinct JWS purposes from licensing. Clients start with an embedded trusted root, containing independent root and release roles. Root changes require sequential versions, threshold signatures from both old and new root roles, and fresh metadata. Release metadata binds product, platform, channel, monotonic sequence, display version, minimum supported sequence, artifact digest/size, SBOM/provenance digests, issued time and expiry. The public root defines allowed artifact origins and the verification threshold. Root and release roles cannot share key IDs or public keys.

Clients persist root, per-target sequence/digest watermarks and last-observed time in protected state; operations must be serialized by the host across processes. A lower sequence, same-sequence different metadata, stale root/manifest, wrong binding, unknown key, clock rollback, or bad signature fails closed. Equal metadata may be retried until expiry. A signed pause preserves watermarks while preventing download. Root rotation clears no release history. Expiry bounds freeze attacks but a disconnected client cannot know a new revocation until it receives fresh roots.

Artifact downloads are HTTPS-only, origin-allowlisted, without redirects, and stream into a private temporary directory with a configured size/time limit. The signed size and SHA-256 must match before returning a staging path. Failed or interrupted downloads remove temporary data. Installation and platform code-signature checks are host responsibilities; no downloaded bytes execute automatically. Provenance/SBOM digests bind metadata, but digest presence alone is not verification of a build's provenance.

This is a bounded signed-update protocol, not a claim of TUF conformance. Production root custody, KMS/HSM signing, immutable storage, OS installation/recovery and operational rotation drills are external prerequisites. Test software signers never establish production custody.

## Billing provider

Paddle's official OpenAPI is the provider wire contract. Checkout uses server-selected catalog price IDs, a server-created intent correlation ID, automatic collection and fixed HTTPS API destinations. No client price, amount, currency or entitlement is trusted. Provider transaction creation does not itself grant licensing state. Returned checkout URLs must use the configured approved payment-link origin; the default payment-link website hosts Paddle.js.

The published transaction-create specification does not document an idempotency header. Do not invent one or automatically retry a request after an ambiguous response. Persist an intent before calling, permit one creation attempt, and reconcile uncertain outcomes against verified provider data. Webhooks require signature verification, durable event identity, explicit intent/subscription mapping, and ordered commercial-state application before they can change access. Server adapters alone are not live checkout or settlement.

## Initial checkout and commercial event application

The first checkout upgrades an existing subscription-backed license (including a trial) for an organization administrator/owner. One intent per license prevents a second recurring subscription; plan change checkout and replacing a canceled provider subscription require a future explicit workflow. An intent has one server-selected Paddle price and a hashed caller operation ID. Under license → checkout lock order, reservation and audit commit before exactly one provider creation attempt. A crashed or failed submission remains submitting/uncertain until an operator provides a candidate transaction ID with a mandatory reason; the adapter verifies the provider's intent, price and payment URL before recording it. No automatic resubmission follows an ambiguous outcome.

Verified `transaction.completed` establishes the provider subscription binding, changes the existing subscription to the mapped plan and active paid period, and converts a trial license to subscription kind. Subsequent supported subscription events update that same binding; past-due and paused states restrict access through existing licensing policy. A signed notification never clears a license's suspended/revoked state. Unknown mappings and mismatched provider price/identity fail closed for reconciliation. Active events require a future paid-period boundary. Equal-time distinct notifications require reconciliation rather than arbitrary event-id sorting; older notifications are retained as ignored. Event receipts, commercial changes and audit append commit atomically. Raw provider bodies and PII are not stored or logged; only event identity, timing and body digest are retained.

Paddle settings are optional as a complete group; partial configuration fails startup. Sandbox/live API destination is explicit and fixed. In production, apply migration 0009 and app grants, complete seller approval and payout checks, configure approved Paddle.js payment-link hosting, map catalog prices to local plan IDs, then prove webhook delivery and reconciliation in sandbox before enabling live credentials. No production billing setting is changed by this code release.

## Isolated payment page

The `/checkout` page loads Paddle.js from its official CDN, accepts only a syntactically valid transaction ID and fetches an explicitly configured public client token. Its narrowly scoped CSP admits Paddle resources only on this payment page; the account portal retains its self-only script policy. Public client-token configuration is validated separately from API/webhook secrets and against sandbox/live mode. Browser completion messages do not grant access; signed mapped notifications remain the authority. No customer bearer token is persisted on the payment page.
