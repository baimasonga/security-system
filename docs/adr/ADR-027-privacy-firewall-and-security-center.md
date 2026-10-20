# ADR-027: Privacy firewall and security center

Status: accepted. Affects trust boundaries: **yes** (data entering the platform from clients).

## Context

[architecture/09](../architecture/09-advanced-feature-requirements.md#privacy-and-workspace): the privacy firewall
validates allow-listed telemetry schemas and rejects document content, personal identifiers and secrets; a
security center explains permissions, device state and collected signal categories.

## Decision

**Privacy firewall** (`packages/telemetry/src/firewall.ts`).

- Clients may send only `app.started {app_version, platform}`, `feature.used {feature, duration_ms}` and
  `app.error {code, component}` through `POST /v1/telemetry/events` (signed-in, rate-limited, ≤ 50 events).
  Every string has a length bound and a strict pattern (identifiers, versions); numbers have ranges.
- Unknown events and unknown attributes are **refused**, not silently dropped, so a client cannot believe it
  shipped data that the platform kept.
- Independent content detectors run on every string even when its pattern would already reject it (a future,
  looser pattern must not open a hole): email, URL, file path, phone, payment card (Luhn), token/secret shapes
  (JWT, `sk_…`, long mixed-class runs) and key material. Inputs are length-bounded before any pattern runs.
- Refusals return `{index, violations: [{field, rule}]}` and increment `telemetry_firewall_rejected_total{rule}`;
  the refused value is never echoed, logged or stored.
- Accepted client events are stored as `client.<name>` with **no user reference** (data minimization).
- Server-side `Telemetry.track` string attributes pass the same detectors; a suspicious value is dropped.

**Security center** (`GET /v1/security-center`, portal page): for the signed-in person only — account protection
(email verified, authenticator, passkeys, operator), each organization's role with the plain-language meaning of
every permission it grants (`PERMISSION_DESCRIPTIONS` next to the RBAC table), the person's own active devices with
posture and attestation status (ADR-026) and how long each works offline, the data categories the platform keeps
with purpose and retention (`DATA_CATEGORIES`, kept in code so it changes with the code), and recommendations.

The portal also exposes the existing account actions here: request a verification email,
enroll/disable an authenticator, register/remove passkeys and sign out. Own active devices
can be deactivated after confirmation, with an explicit warning that existing offline leases
remain valid until expiry. Organization cards link to that organization's member management
and, for `ops:read` roles, application monitoring. These controls reuse existing authorized,
audited APIs and deployment configuration; no new permission, credential, mutation endpoint or
automatic remediation is introduced. Unconfigured protection methods explain their availability.

## Consequences

- Detectors are heuristics: they over-refuse rather than under-refuse, and the allow-list is the primary control.
- Adding a client event or field is a reviewed code change to the schema, with tests.
