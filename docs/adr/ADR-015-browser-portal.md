# ADR-015 — Same-origin customer portal and operator console

Status: Accepted. Affects trust boundary: browser and API.

The API now serves an accessible browser portal at `/` with explicit local assets. Customer licenses, devices, organization membership and trials use existing tenant-scoped API permissions. Operators provision products/plans/subscriptions/licenses and inspect audit/metrics through existing operator-only endpoints, preserving mandatory reasons. Catalog browsing requires authentication and contains no license keys or tenant records.

## Browser controls

The portal uses external ES modules/styles and textContent/DOM construction, not injected HTML. HTML CSP allows only same-origin scripts, styles and API requests and forbids embedding, inline scripts, eval and base URL changes. API responses retain their existing restrictive CSP. Asset paths are explicit constants, never filesystem paths derived from requests. Tokens remain in memory, not persistent browser storage; logout revokes them server-side and reload forgets them. One-time license keys appear in a dismissible dialog and are cleared on dismissal.

The device demo generates a non-extractable Ed25519 software key with WebCrypto and stores it in IndexedDB. Its private key never leaves the browser. Public-key thumbprints and challenge messages match the SDK/server wire contract. It caches verification keys at activation and validates algorithm, signature, claims, product/installation/key binding, expiry and a monotonic clock high-water mark before exposing entitlements. This is a demonstrator, not hardware attestation or the future signed-root trust distribution. Browser storage loss means a new device identity; users can release the prior slot through authorized device management. Local software cannot protect against a compromised browser/OS.

## Evidence

HTTP tests verify public static content, CSP separation, authenticated catalog access, missing objects and absence of plaintext license keys in catalog responses. Browser-verifier tests reject tampering, wrong bindings and invalid time/claim states. Real Chromium checks registration/login/logout, team creation, operator provisioning, one-time license issue, device activation/refresh/offline verification/deactivation and mobile overflow. No database state schema or locking changes are introduced in this slice.
