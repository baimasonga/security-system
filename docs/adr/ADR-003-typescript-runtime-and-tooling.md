# ADR-003 — TypeScript on Node ≥ 22.18 with native type stripping, no build step

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: no

## Context

We want the most boring, auditable toolchain: what runs in production should be
exactly the source reviewed, with minimal moving parts and dependencies.

## Decision

- TypeScript is the implementation language (Go remains an option for a future
  high-assurance signing service; ports make that swap clean).
- Code is **erasable-syntax-only** TypeScript (`erasableSyntaxOnly`, no enums,
  no parameter properties, no namespaces), imported with explicit `.ts`
  extensions, and executed by Node's native type stripping — **no transpile or
  bundle step**; `tsc --noEmit` is the type gate; Vitest runs the tests.
- npm workspaces; packages expose `src/index.ts` via `exports`.
- Runtime dependencies are deliberately few: `fastify`, `zod`,
  `@fastify/rate-limit`, `pg`. Cryptography uses `node:crypto` only.
- Quality gates: Prettier, ESLint (typescript-eslint + eslint-plugin-security),
  the boundary checker, `tsc`, Vitest, `npm audit`, secret scanning, CodeQL.

## Consequences

- No build artifacts to tamper with; stack traces map to source.
  − Requires Node ≥ 22.18 in all environments (pinned in `engines`, Dockerfile, CI).
  − Client SDKs for .NET/Rust/Dart (later) cannot share this code; the lease
  format (ADR-002) and the test vectors in `docs/api/lease-test-vectors.json`
  are the cross-language contract.
