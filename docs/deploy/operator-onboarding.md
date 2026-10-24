# Current operator onboarding

This is the current user-flow guide. Older rollout checkpoints describe earlier
releases and must not be used as step-by-step onboarding instructions.

## Account protection

The Account page reports whether authenticator protection is enabled. Creating an
entry on a phone is not activation. Start setup with the Warrior account password.
Warrior displays a manual setup key; this implementation does not render a QR code.
Add that exact key as a time-based authenticator entry with six digits and a
30-second period. Confirm on Warrior with the password again and the new entry's
current code, within ten minutes. Starting setup again replaces the pending key;
older pending entries will no longer match. An enabled factor cannot be overwritten
by beginning setup. Keep an existing phone entry until its replacement is confirmed.

Successful activation revokes all sessions and displays ten recovery codes once.
Save them privately, then sign in with the password and a fresh unused code.
Recovery codes work for account recovery/login but not privileged credential
step-up. A code consumed by login cannot be reused for issuing a credential.
Navigation removes the displayed setup key; restarting generates a different key.
No secret belongs in support screenshots, logs or chat.

## Application connection

The hierarchy is workspace -> application -> environment -> component. Opening an
application, then adding production creates its environment. Register application
creates another independent application. Components belong to one environment;
dependencies refer to other components in that environment, not service URLs.
Registration is inventory, not discovery, monitoring or commercial provisioning.

Credential management checks the signed-in account's current MFA status. When MFA
is missing it shows the prerequisite and an Account action. The server always
rechecks authority and a fresh code, regardless of what the UI displays. Existing
credential metadata remains readable. Emergency revocation still requires MFA and
remains supported by the server for disabled/archived parents.

For Rokela PDF, register api, converter and scanner. Issue an environment-scoped
`events:write` credential after MFA activation. Privately install the token and
three public component IDs in the PDF main application's server-side WARRIOR
settings. See [the integration brief](../integrations/rokela-pdf.md). Configure
rules and verify real acknowledged events and failure/recovery before declaring it
connected. Unknown health means no eligible fresh observation, not healthy.

## Capability and activation matrix

| Capability                                                 | Source implementation          | External activation/evidence                                                                                                                                 |
| ---------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Accounts, organizations, roles, MFA                        | Implemented                    | Each account must finish enrollment; deployment requires a stable MFA key.                                                                                   |
| Passkeys and identity mail                                 | Implemented, optional          | Require their origin/provider configuration; external federation remains separate work.                                                                      |
| Licensing, devices, quotas, seats, signed updates          | Implemented                    | Billing providers, production signing custody and native acceptance remain separate gates.                                                                   |
| Application inventory and credentials                      | Implemented                    | Owner/admin scope and MFA required; inventory does not connect a source.                                                                                     |
| Durable events, health/history, incidents, automatic rules | Implemented, feature-gated     | Real source binding and controlled failure/recovery acceptance required.                                                                                     |
| Portal notifications                                       | Implemented                    | Incident email is implemented behind an opt-in flag; provider settings, verified recipient and inbox acceptance are required. Webhooks remain separate work. |
| Scan/recovery evidence and collector                       | Implemented                    | Imports remain administrator reports, not independent attestation.                                                                                           |
| Public release observer                                    | Implemented and exercised      | Checks health/readiness and public UI hashes, not authenticated workflows.                                                                                   |
| Recurring isolated restore exercise                        | Implemented and exercised      | Synthetic logical restore is not production PITR, key recovery or RPO/RTO.                                                                                   |
| Sharing and short links                                    | Implemented, optional          | Storage/scanner/provider configuration and independent acceptance required.                                                                                  |
| Cloudflare alternative                                     | Prepared with traffic disabled | Requires provider provisioning, secrets and controlled acceptance.                                                                                           |
| Automatic infrastructure remediation                       | Deferred                       | Not enabled by registration, alerts or a factory reset.                                                                                                      |

Audit anchoring requires an independent protected witness; follow the
[production witness setup](audit-witness-setup.md). A disabled-anchoring warning
must remain visible until accepted external publication is active.

## Factory-reset boundary

A factory reset is an explicitly authorized destructive maintenance operation. It
is not a normal deployment, schema migration or UI-preference reset. Confirm the
exact database/project, private Warrior schema and any Warrior-owned object-store
resources before constructing executable deletion commands. Do not reset a whole
shared Supabase project or shared bucket. The separate Rokela PDF application and
its database/files are outside Warrior reset scope.

Stop API/background writers for the operation. Inventory the actual target and
rollback/recovery access, remove the explicitly selected Warrior data, rebuild the
schema through the reviewed predeploy runner, and verify grants/profile checks.
Factory reset removes accounts and operator roles: re-register the owner, then use
the audited bootstrap tool to restore operator status before enrolling MFA anew.
Keep signing, encryption, database and provider credentials outside the reset;
replacing them is a separate operation. Blob cleanup and database deletion must
be planned together to avoid orphaned objects or deletion of shared application
files. No ordinary GitHub push may execute a factory reset.

The current request authorizes deleting Warrior application data, but execution
remains blocked until its actual database/project and maintenance access can be
verified. No destructive command is supplied for an unidentified target.

## Safe support diagnostics

Credential mutation refusals emit a fixed error category, generated request
reference and status. The category/reference are also in the log message so a
flattened provider export remains useful. No raw request body, MFA factor, token,
unknown field, path or exception is included. Client responses retain their safe
problem format and cross-tenant error semantics.
