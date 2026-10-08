# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue. Email the security owners (set the real address
before launch: `security@<your-domain>`) with a description, reproduction steps and
impact. We aim to acknowledge within 2 business days. Do not test against production
data you do not own; do not exfiltrate customer data.

## Scope notes

- This repository is a V1 first slice; see the residual-risk register in
  [docs/threat-models/01-v1-licensing-and-activation.md](docs/threat-models/01-v1-licensing-and-activation.md)
  for known, accepted gaps before reporting them.
- Secrets: never commit keys, peppers or tokens. CI runs secret scanning and the repo's
  boundary check fails on private-key material.

## Non-negotiable invariants

See [docs/security/invariants-traceability.md](docs/security/invariants-traceability.md).
