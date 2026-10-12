# Feature implementation program

## Source and limits

The requested scope is every intended feature. Inventory source: architecture/01-system-context.md, architecture/02-domain-model.md, architecture/05-v1-status-and-handoff.md, existing API and SDK. These refer to an original numbered brief that is not present in the checkout. Several later contexts have names but no behavioral specification. This inventory preserves those requirements rather than claiming that a prototype implements them.

## Current slice

Portal, operator console and device demo are implemented locally against existing API flows. Authenticated catalog browsing is added to the API. Chromium verification exercises account/team/provisioning/device workflows; application and PostgreSQL suites verify security boundaries. ResendMailDelivery and MemoryMailDelivery implement a tested delivery seam; PaddleWebhookVerifier validates original-byte HMAC signatures and timestamps. Email verification and password-reset endpoints are implemented, including durable token state and session revocation; they are enabled only when Resend sender/key/origin are configured. Billing and external sign-in are not enabled. Authenticator MFA is implemented with encrypted secrets, single-use recovery codes, replay prevention, session revocation and optional operator enforcement (ADR-017). Passkeys and durable delivery retry remain pending.

## Capability map and delivery order

| Module                  | Scope                                                                                     | Acceptance evidence                                                                   | Dependencies                            |
| ----------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------- |
| portal                  | Register/login/logout; organizations/members; licenses/entitlements/devices/trials        | Browser flows against real API, tenant and role refusal tests                         | identity/licensing                      |
| operator-console        | Catalog, subscriptions, issue/state transitions, audit, metrics and anchors               | Operator authorization; reasons and audit on mutations                                | portal                                  |
| device-demo             | Ed25519 challenge/activation, validation, refresh, deactivate, offline lease verification | API roundtrip, invalid signature/binding rejection                                    | licensing/SDK                           |
| identity-hardening      | Verification/reset, MFA/passkeys, session rotation                                        | One-use expiring tokens, generic recovery responses, session revocation and MFA tests | delivery provider and identity spec     |
| commercial-controls     | Capabilities, quotas, enterprise seats, billing webhooks, offline transfer                | Atomic consumption, tenant isolation, replay protection, provider signatures          | billing specification                   |
| device-trust            | Passport, hardware-backed keys, trust scores, clone signals, policy decisions             | Real attestation adapter, explicit policy and threat model                            | original milestone-2 brief              |
| release-security        | Signed trust distribution/updates, SBOM, provenance                                       | Root/rotation/rollback verification, download integrity                               | original milestone-3 brief, storage/KMS |
| privacy-security-center | Privacy firewall and security center                                                      | Defined content/data rules, consent and enforcement tests                             | original milestone-4 brief              |
| workspace               | Temporary workspace                                                                       | Isolation, expiry/deletion, storage and recovery tests                                | original milestone-5 brief, storage     |
| privileged-operations   | JIT elevation, dual control, freeze                                                       | Distinct approvers, expiry/replay/concurrency tests and audited state                 | original milestone-6 brief              |

## Browser boundary

Same-origin static portal served by the existing API at `/`. No new frontend build dependency. External local script/style assets only; no inline script, eval, unsafe HTML insertion, or third-party assets. Bearer sessions stay in memory and are lost on reload. Existing API remains the authorization boundary; hidden UI controls never supply authorization. Display only API-returned data. Public HTML contains no tenant/private material. Sensitive one-time license keys are shown once and never persisted in browser storage. Mobile and keyboard interactions must remain usable.

## Infrastructure requirements

A local adapter is not evidence of email delivery, payment settlement, hardware attestation, immutable witnesses, or backup recovery in production. Provider choice and secure settings are required; never ask for credentials in chat. Deployment follows tested local work, not unverified feature stubs. Do not advertise planned advanced milestones as active product features.
