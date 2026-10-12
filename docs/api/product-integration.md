# Connect a Software Product

Register each application as a product with a stable product code in the operator console. Create plans with resolved feature entitlements, device limits, offline lease policy, and optional numeric `_monthly` allowances. Issue the customer's license under their organization and subscription, or use the implemented trial flow. Customer accounts and organization membership authorize initial activation.

## Node and Electron Applications

`@trust/sdk-core` is currently a private workspace package, not a published npm distribution. Integrate it from a controlled checkout or package it internally with its workspace dependencies. It requires Node 22.18 or newer; use it in Electron's main process, with a narrow IPC interface to the renderer. The Node crypto implementation is not directly browser-compatible. The portal device example uses WebCrypto separately.

Construct `TrustPlatformClient` with your HTTPS platform URL, product code, a trusted public signing-key bundle, and a host implementation of `SecureStore`. Store the installation identity, device private key, lease, and clock watermark in OS-protected storage. Do not use a plain JSON file or browser localStorage for production secrets. Deliver and update public verification keys through a trusted release/configuration channel; downloading keys from an untrusted URL does not establish trust. Platform signing private keys, database credentials, operator sessions, and provider secrets must never ship with products.

1. Sign the customer in through `/v1/auth/login`, including their MFA factor if enabled. Keep their session token protected.
2. Call `activate(sessionToken, licenseKey)` once for the installation. The SDK generates the device identity, signs a challenge, and verifies the returned lease's signature and bindings before storing it.
3. At startup and appropriate intervals, call `maintainLease()`, then `getEntitlements()`. Handle definitive server refusals; transient connectivity failures retain only the existing time-bounded lease.
4. Enable features from resolved entitlement keys, not plan names. Only usable leases expose entitlements. On expiry or invalid state, offer a documented restricted mode that preserves viewing/export and user files.
5. Call `deactivate()` when the customer releases a device slot. Signing out of an account is a separate action.

Hardware attestation, secure update delivery, and capability issuance are not implemented SDK methods. Software-held device keys do not imply hardware-backed protection. Local feature checks are defense in depth; enforce sensitive cloud operations on your backend.

## Online Monthly Quotas

The SDK exposes `getUsage(sessionToken, orgId, licenseId)` and `consumeQuota(sessionToken, orgId, licenseId, { entitlement, units, idempotencyKey })`. Results retain the API's snake_case fields and ISO timestamp strings. Both methods require an authenticated session with the appropriate organization permission. They do not consume offline leases or provide offline spending authority.

For example, a backend handling OCR should authenticate the user, derive the organization and license from authorized context, determine the page count itself, and persist one operation ID for the logical job. Consume `ocr_pages_monthly` using that ID, then durably deduplicate job execution. Reuse the same ID and payload on retries, even after process restart; changing the payload conflicts. A quota receipt is accounting evidence, not an execution capability, payment receipt, or proof the job ran. Never accept a client-provided receipt as sole authorization.

No OCR/AI execution pipeline, automatic refund workflow, or payment checkout is supplied by this integration. Resolve crash recovery and charge-versus-execution semantics in the product backend before charging real jobs. Display usage as informational; a positive remaining allowance is not permission to execute.

See [monthly quota contracts](monthly-quotas.md) for wire requests and [OpenAPI](openapi.yaml) for the complete API. C#, Java, Python, and mobile clients can implement the same protocol; validate their lease verification against [the interoperability vectors](lease-test-vectors.json) before release.

## Deployment Verification

Apply migrations and least-privilege grants before using new endpoints. Test customer activation, wrong-product leases, expiration, revocation, device limits, offline behavior, quota exhaustion, replay, and another organization's IDs in a staging environment. A passing GitHub workflow does not establish successful authenticated production integration.

## Windows, Billing and Updates

Windows hosts can use `new WindowsDpapiStore(productCode)` for protected SDK state. The adapter invokes the system Windows PowerShell executable with a static script; secrets travel on stdin and records are encrypted with CurrentUser DPAPI. It restricts its directory to the current user's SID and atomically replaces encrypted records. Windows CI runs a native round-trip/tamper test. DPAPI is OS-protected storage, not verified TPM attestation, and it does not defend against code already running as that user.

For a native key service, pass `deviceKeyProvider: async installationId => deviceKey`. Signing may return a Promise. The provider must return the same persistent Ed25519 key for that installation; a failure never falls back to a new software identity. The SDK validates public-key/thumbprint binding and strips private JWK members before transport. It serializes key creation within an instance; the host must serialize across instances/processes. A Windows TPM using only P-256 needs a separately versioned server protocol and a validated attestation chain; that protocol is not implemented here.

The SDK also provides `createCheckout(sessionToken, orgId, licenseId, planId, operationId)` and `getCheckout(sessionToken, orgId, licenseId)`. See [billing checkout](billing-checkout.md) for provider prerequisites and the payment-authority boundary. Use [SecureUpdateClient](secure-updates.md) separately from licensing for signed feed verification and artifact staging.
