# Threat Model — Device trust (ADR-026)

Test shorthand: **DP** = `packages/licensing/test/device-policy.test.ts`, **DT** =
`services/platform-api/test/device-trust.test.ts` (also on PostgreSQL as superuser and least-privilege role),
**CON** = licensing store contract. Twelve controls were mutation-checked (each break made a test fail).

| ID   | Threat                                                       | Mitigation                                                                                                | Evidence    |
| ---- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ----------- |
| DT-1 | A device claims to be trustworthy                            | Only server-observed signals exist; attestation reported `unknown` until a verified adapter exists        | DT, ADR     |
| DT-2 | A score overrides revocation / tenant / signature invariants | License evaluated first; DENY passes through unchanged; posture never yields SUSPEND/DENY                 | DP, DT      |
| DT-3 | Cloned device key used from several installations            | Installation switches → OBSERVE → STEP_UP_AUTH; enforce mode blocks until the person re-activates         | DP, DT      |
| DT-4 | Key-guessing / tampering attempts against one device         | Failed proofs and installation mismatches → OBSERVE → RESTRICT (24 h offline leases)                      | DP, DT      |
| DT-5 | Policy locks people out or destroys data                     | Observe mode by default; deactivation always works; nothing deletes data; posture relaxes as windows pass | DT          |
| DT-6 | Stale posture after signals age out                          | `review_at` triggers recompute on read                                                                    | DT          |
| DT-7 | Passport leaks across tenants                                | `device:read` in the device's organization (404 otherwise)                                                | DT          |
| DT-8 | Evidence kept forever                                        | 90-day retention, purged by maintenance; app role cannot rewrite signals (no UPDATE)                      | CON, grants |

Residual: copying both the device key and its installation state defeats software-only detection (see ADR-026).
