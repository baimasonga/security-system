# Software Trust Platform

Centralized identity, licensing, entitlement, device-trust and (later) secure-update
platform for all desktop and web products. Not a license-key server: the server is
the only authority; clients receive **signed, device-bound, expiring evidence** they
can verify offline with public keys.

> **Status: V1 first slice, development-grade.** The license lifecycle works end to
> end and is heavily tested, but persistence is in-memory and production start-up is
> refused until the PostgreSQL adapters land. Read
> [docs/architecture/05-v1-status-and-handoff.md](docs/architecture/05-v1-status-and-handoff.md)
> before relying on anything here.

```
Product → Plan → Subscription → License → Device → Activation → Signed Offline Lease → Validation
```

## Quick start

Requires Node ≥ 22.18 (native TypeScript type stripping; no build step).

```bash
npm ci
npm run check        # format, lint (+ architecture boundaries), typecheck, unit/integration/security tests
npm run test:db      # PostgreSQL schema tests (spins up a throwaway local cluster; or set DATABASE_URL)
npm run dev          # API on http://127.0.0.1:8080 with ephemeral dev-only keys and in-memory stores
```

## How a device is licensed

```
operator:  create product/plan/subscription → issue license (key shown once)
customer:  register/login                                   (session)
device:    generate Ed25519 key + installation id
           POST /v1/devices/challenges                      (single-use nonce)
           POST /v1/licenses/activate  session + license key + signature over nonce
server:    license state? subscription entitling? device limit? canary? key conflict?
           → register device → sign lease (bound to product, installation, device key)
offline:   sdk-core verifies the lease with the public trust bundle (skew/rollback aware)
online:    POST /v1/licenses/{validate,refresh,deactivate}  device-signed challenge, no bearer token
```

Using the SDK:

```ts
import { TrustPlatformClient, MemorySecureStore } from '@trust/sdk-core';
const client = new TrustPlatformClient({
  baseUrl,
  productCode: 'pdf-pro',
  trust /* pinned bundle */,
  store,
});
await client.activate(sessionToken, licenseKey);
const { state, capabilities } = await client.getEntitlements(); // works offline
await client.maintainLease(); // refresh when due, tolerant of outages
```

## Repository layout

```
packages/
  shared-types   kernel: ids, errors, Decision enum, lease claims contract, redaction
  crypto         Ed25519 JWS, key lifecycle (KeyRing), license-key HMAC; /verify = client-safe subset
  audit          hash-chained tamper-evident audit log
  telemetry      allow-listed, pseudonymized telemetry and security signals
  auth           users, sessions, organizations, RBAC
  entitlements   pure plan → entitlements/capabilities resolver
  licensing      subscriptions, licenses, devices, activations, challenges, leases, policy
  sdk-core       device key, lease verifier, API client (ships to untrusted machines)
services/platform-api   Fastify HTTP edge, config, composition root, SQL migrations
docs/            architecture, ADRs, threat model, OpenAPI, key management, runbooks
tests/           security (tenant isolation, privilege) and integration (real socket) suites
tools/           boundary checker, ephemeral Postgres runner, lease-vector generator
```

Dependency direction is enforced mechanically (`npm run lint`); see
[docs/architecture/01-system-context.md](docs/architecture/01-system-context.md).

## Documentation

Start at [docs/README.md](docs/README.md). Security reporting: [SECURITY.md](SECURITY.md).
Contributor/agent rules: [CLAUDE.md](CLAUDE.md).
