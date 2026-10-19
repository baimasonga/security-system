# ADR-022: Privileged operations — dual control, JIT grants, freeze and break-glass

Status: accepted. Affects trust boundaries: **yes** (operator authority).

## Context

Until now one platform operator could perform every administrative change alone, including irreversible ones
(revoking a license) and ones that expand authority (making another user an operator, which was possible only
from deployment tooling). A single stolen operator session, or a single mistaken operator, could do lasting
damage. The requirements in [architecture/09](../architecture/09-advanced-feature-requirements.md#privileged-operations)
ask for just-in-time grants bound to a requester, an exact operation and a reason; approval by a distinct
MFA-authenticated operator; a freeze that stops defined writes while reads keep working; and a bounded,
independently witnessed break-glass path.

## Decision

### Requests are the JIT grants

A **privileged request** names one operation from a closed list, its exact target and a mandatory reason. The
target is validated when the request is created and stored with it; execution uses the stored target, never new
client input, so an approval covers exactly what the approver saw.

| Operation           | Target                 | Dual control                                 |
| ------------------- | ---------------------- | -------------------------------------------- |
| `license.revoke`    | organization + license | when `PRIVILEGED_DUAL_CONTROL=true` (staged) |
| `operator.grant`    | user                   | always                                       |
| `operator.revoke`   | user                   | always                                       |
| `org.unfreeze`      | organization           | always                                       |
| `platform.unfreeze` | —                      | always                                       |

Lifecycle: `pending` → `approved` → `executed`, or `rejected` / `cancelled` / `expired` / `failed`. A pending
request expires after 24 hours; an approval opens an execution window of one hour (the JIT grant). Only the
requester can execute or cancel; the requester can never approve or reject their own request. Every transition
happens under the request's row lock with its audit event in the same transaction, so a request is approved once
and executed at most once — a replayed approve or execute fails with `conflict`.

### Approval needs a distinct operator and a fresh second factor

The approver must be a different active platform operator with authenticator MFA enabled, and must submit a
current TOTP code with the approval. The code goes through the same replay-protected counter as login
(`AuthService.stepUp`, ADR-017): it is consumed once, failures count toward the account lockout, recovery codes
are not accepted. A session alone never approves anything.

### Execution is at-most-once

Operations owned by this module (`org.unfreeze`, `platform.unfreeze`) change state in the same transaction that
marks the request executed. Operations owned by another bounded context (`license.revoke` in licensing,
`operator.*` in identity) are claimed first: the request moves to `executing` and is audited, then the operation
runs in its own transaction with its own audit event naming the request, then the request is marked `executed`
or `failed`. A crash between the steps leaves the request `executing` (visible, never re-runnable): a fresh request
is needed. Re-running an operation is never possible by retrying a request.

### Freeze

A freeze stops writes that **grant or extend access**, effective for requests that start after it commits:

- organization freeze: issuing licenses, reinstating licenses, creating or changing subscriptions, adding members
  to that organization, starting trials;
- platform freeze: all of the above for every organization, plus product and plan changes and `operator.grant`.

Reads, exports, device activation, validation, lease refresh and deactivation, suspension and revocation keep
working: a freeze is a containment tool and must never lock users out of their documents or licenses. Freezing is
immediate (one operator, reason, audited) because it only restricts; lifting a freeze always requires dual control.
Refusals return `423 frozen`; a customer route checks membership first, so outsiders still get `404` and never
learn that an organization is frozen. Payment-provider notifications are still recorded during a freeze (a paying
customer is not the threat a freeze contains).

### Break-glass

When the second operator is unavailable, the requester may approve their own request through break-glass. It is
bounded and witnessed:

- it requires a fresh TOTP code, a reason, and external audit anchoring (ADR-010) to be configured — without an
  external witness break-glass is refused;
- the grant is valid for 15 minutes, and an operator may use break-glass at most once per 24 hours;
- the approval is audited (`privileged.break_glass`), then an audit anchor that includes that event is published to
  the external witness; the request can be executed only after the anchor is published
  (`privileged.break_glass_witnessed`). A failed publication leaves the grant unusable.

## Consequences

- Operators can now be promoted without shell access to the deployment, but never by one person.
- `PRIVILEGED_DUAL_CONTROL=true` makes the direct revoke endpoint refuse with `409` and `details.approval_required`;
  enable it once at least two operators have enrolled MFA (staged like `REQUIRE_OPERATOR_MFA`).
- Request rows are kept (no purge): they are part of the operator accountability record, as are the audit events.
- A freeze is checked at the API boundary before the write's transaction starts; a write already in flight when the
  freeze commits completes. This is documented, not hidden.
- Not covered: approval quorums larger than two, time-of-day policies, hardware-key (passkey) step-up. Passkeys
  are tracked separately.
