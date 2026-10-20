# Security Center controls

The signed-in **Security center** page supports these existing account actions:

- Request a verification email when delivery is configured and the email is unverified.
- Enroll an authenticator and receive one-time recovery codes. Enrollment signs out
  all sessions; sign in again with an unused authenticator or recovery code.
- Disable an authenticator using the password, an unused code and a reason. This
  also signs out all sessions.
- Register or remove a passkey when WebAuthn is configured and supported by the browser.
  The page stays in Security Center after either operation.
- Deactivate a listed own device after confirmation. Existing offline leases remain
  valid until expiry; deactivation frees the activation slot and prevents renewal.
- Open an organization's management page, or its Applications monitoring page when
  the role grants `ops:read`. The selected workspace changes to that organization.
- Refresh account/security evidence or sign out.

These controls use the existing authentication, device and authorization APIs. No
new permission, database migration, feature flag or secret is required by this UI
change. Unconfigured authenticator/passkey methods explain their availability.
Verification delivery remains subject to the existing throttles and provider setup.
Only fake/local mail and a virtual WebAuthn authenticator were used in verification.

The page remains the person's account/device security view. Applications is the
organization monitoring workspace. Incident handling, scanners and automatic
remediation are not supplied by these buttons. Ingestion/health rollout gates and
the previously recorded heartbeat freshness review findings remain separate.

Navigation, sign-out or a different session invalidates pending protection views.
Late enrollment responses cannot show recovery codes in the new view. Setup keys,
recovery codes, passwords and passkeys are not written to browser storage.

## Verification and rollback

Run `CHROMIUM_PATH=/path/to/chromium npm run test:portal`, `npm run check`, and the
existing MFA/passkey/privacy/device-trust PostgreSQL suites as both owner and app role.
Browser tests cover real enrollment/disable, verification to fake mail, WebAuthn
registration/removal, device cancellation/deactivation, member restrictions, workspace
selection and a delayed recovery-code response after leaving the view.

No transaction, schema, retention, lock or quota behavior changed, so a new load
scenario is not applicable. The delayed-response guard is mutation-checked in a
disposable source copy. Roll back by reverting the portal UI change; retain existing
account protection, device/audit state and deployment configuration.
