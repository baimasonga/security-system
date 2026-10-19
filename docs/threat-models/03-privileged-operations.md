# Threat Model — Privileged operations (ADR-022)

Scope: operator authority — dual-control requests (JIT grants), freeze and break-glass. Test shorthand: **PS** =
`packages/privileged/test/service.test.ts`, **PC** = `store-contract.ts` (memory + PostgreSQL), **PA** =
`services/platform-api/test/privileged.test.ts` (also on PostgreSQL as superuser and as the least-privilege role).
Every row marked _mutation-checked_ was verified by breaking the control and watching the test fail.

| ID    | Threat                                                         | Mitigation                                                                                                                               | Evidence                                                                 |
| ----- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| PO-1  | One stolen operator session revokes licenses or adds operators | `license.revoke` (with `PRIVILEGED_DUAL_CONTROL`), `operator.*` and unfreeze need a second operator; the requester can never approve     | PS, PA "distinct operator" (mutation-checked)                            |
| PO-2  | Approver's session alone approves (no second factor)           | Approval consumes a fresh TOTP code under the user lock; recovery codes refused; failures count toward lockout; MFA required             | PA "never accepts the same code twice", "without MFA" (mutation-checked) |
| PO-3  | Approval covers something other than what was shown            | Operation and target stored at creation and validated; execution uses only stored values; closed operation list                          | PS "exact target", PA malformed requests                                 |
| PO-4  | Replay: approve or execute twice                               | Transitions under the request row lock with audit in the same transaction; external operations claimed (`executing`) before running      | PS, PC concurrency, PA replay (mutation-checked)                         |
| PO-5  | Another operator uses someone's grant                          | Only the requester executes or cancels                                                                                                   | PS, PA (mutation-checked)                                                |
| PO-6  | Stale approvals used much later                                | Pending requests expire after 24 h; grants after 1 h (break-glass 15 min)                                                                | PS "expires"                                                             |
| PO-7  | Break-glass abused to bypass dual control                      | Needs external anchoring; fresh code; once per operator per 24 h; unusable until the external witness acknowledges an anchor covering it | PS, PA break-glass (mutation-checked)                                    |
| PO-8  | Compromised admin keeps changing a tenant during an incident   | Freeze stops grant-extending writes immediately; lifting needs dual control                                                              | PA freeze (mutation-checked)                                             |
| PO-9  | Freeze locks users out / destroys data                         | Reads, device activation/validation/refresh/deactivation, suspension and revocation unaffected; nothing deleted                          | PA "containment and reads work"                                          |
| PO-10 | Freeze state leaks to outsiders                                | Customer routes check membership first (404), then the freeze                                                                            | PA outsider 404 (mutation-checked)                                       |
| PO-11 | Erasing the accountability record                              | App role has no DELETE on `privileged_requests`; audit log append-only                                                                   | grants drift test; `db-approle` run                                      |

Residual risks: two colluding operators can still act together (quorum > 2 not supported); a write already in flight
when a freeze commits completes; a crash between claiming and settling an external operation leaves the request
`executing` (visible, never re-run; a new request is needed); emergency removal of an operator out of band
(`revokePlatformAdmin`) remains available to whoever controls the deployment.
