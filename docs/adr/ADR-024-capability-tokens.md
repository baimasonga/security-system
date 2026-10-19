# ADR-024: Capability tokens for processing services

Status: accepted. Affects trust boundaries: **yes** (service authorization).

## Context

Products call separately deployed processing services (OCR, cloud conversion, …). Those services must decide
whether a request is entitled without calling the platform on every request, and without trusting anything the
client says about its plan. The requirement ([architecture/09](../architecture/09-advanced-feature-requirements.md#billing-capabilities-usage-and-seats)):
capability tokens are short-lived, audience/device/license-bound and grant only resolved entitlements.

## Decision

A device asks `POST /v1/capabilities/token {activation_id, installation_id, nonce, signature, capability, service}`.
It authenticates exactly like a lease refresh: a signature with its device key over a single-use challenge whose
purpose is the new `capability` (domain-separated proof message, ADR-002). The server then:

1. evaluates the license (state, subscription, expiry) — a revoked, suspended or lapsed license gets no token;
2. resolves the plan + overrides and checks that the **resolved** capability list contains `capability` — client
   input never adds a capability;
3. signs a compact JWS with header `typ: "cap+jws"` and claims
   `{v:1, jti, iss, aud: "svc:<service>", sub: <activation id>, org, lic, prd, cap, cnf: {jkt: <device key
thumbprint>}, iat, nbf, exp}`, valid for `capabilityTtlSeconds` (default 300 s, clamped to 30–900 s);
4. audits `capability.issued` (refusals: `capability.denied`).

Signing uses the platform's license key (same custody, same trust bundle), separated from leases by explicit
typing (RFC 8725 §3.11): the lease verifier pins `lease+jws` and the capability verifier pins `cap+jws`, so neither
token can be replayed as the other. A dedicated key purpose can be introduced later without changing the claims.

Services verify offline with `verifyCapabilityToken` (sdk-core): pinned algorithm and type, known key, issuer,
exact audience, the exact capability, `exp − iat ≤ 900 s`, at most 60 s clock skew, and — when the service can see
the device's key (mutual TLS or a request signature) — the `cnf.jkt` binding. Services must not cache a token
beyond `exp`.

## Consequences

- Revocation reaches services within one token lifetime (≤ 15 minutes, 5 by default).
- Tokens carry no personal data; `sub` is the activation id.
- Quota consumption remains a separate, atomic online call (ADR-018); a capability token is not a quota grant.
