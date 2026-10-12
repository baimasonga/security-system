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

## Secret-scanning fixture exceptions

Gitleaks retains its default rules. The quota guide's exact public example operation ID is exempt only in that file and only from the generic API-key rule. Public ADR-002 lease vectors are covered by exact historical finding fingerprints in `.gitleaksignore`; this does not exempt an entire file, rule or commit. Regenerated vectors require review. Synthetic credential checks confirm that another credential in the quota guide is still detected. Real credential findings require rotation and remediation, not a fixture exception.
