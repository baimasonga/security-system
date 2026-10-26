import { PERMISSION_DESCRIPTIONS, permissionsFor } from '@trust/auth';
import { CLIENT_TELEMETRY_SCHEMA, TELEMETRY_SCHEMA } from '@trust/telemetry';
import type { UserPrincipal } from '@trust/shared-types';
import type { Container } from './container.ts';

// Security center (ADR-027): one place where a person sees how their account is protected, what each of their
// roles allows, the state of their devices, and which categories of data the platform collects about them.

/** What the platform keeps, why, and for how long. Kept next to the code so it changes with it. */
export const DATA_CATEGORIES = [
  {
    category: 'Optional Android usage analytics',
    contents:
      'App-scoped installation hash, tool categories, app/Android version, device class and approximate IP-derived country; no files, account identity, raw IP or GPS',
    purpose:
      'Aggregate Rokela Android usage and compatibility; reports are unverified client assertions',
    retention: '30 days; mobile settings can stop reporting and clear queued reports',
  },
  {
    category: 'Account',
    contents:
      'Email address, password hash (never the password), authenticator and passkey public keys',
    purpose: 'Signing you in',
    retention: 'Until the account is deleted',
  },
  {
    category: 'Organizations and roles',
    contents: 'Memberships, roles and seats',
    purpose: 'Deciding what you may do',
    retention: 'Until removed; changes are kept in the audit log',
  },
  {
    category: 'Devices',
    contents: 'Public device keys, installation identifiers, activation and lease dates',
    purpose: 'Licensing your software on your devices',
    retention: 'Lease records 90 days after expiry; activations while the license exists',
  },
  {
    category: 'Device security signals',
    contents:
      'Events the server observed (installation changes, failed device proofs, completed re-sign-ins)',
    purpose: 'Detecting cloned or attacked devices',
    retention: '90 days',
  },
  {
    category: 'Usage telemetry',
    contents: `Only these events and fields: ${[
      ...Object.keys(TELEMETRY_SCHEMA),
      ...Object.keys(CLIENT_TELEMETRY_SCHEMA).map((n) => `client.${n}`),
    ].join(
      ', ',
    )}. No document content, names, addresses, file paths or secrets — the privacy firewall refuses them.`,
    purpose: 'Product health and capacity',
    retention: 'Aggregated; never linked to your account',
  },
  {
    category: 'Audit log',
    contents: 'Who changed what and why (no secrets, no document content)',
    purpose: 'Accountability and incident investigation',
    retention: 'Append-only; externally anchored',
  },
  {
    category: 'Shared files',
    contents: 'Files and documents you upload, links and access receipts',
    purpose: 'File sharing you asked for',
    retention: 'As configured per item; see the sharing retention policy',
  },
] as const;

export async function securityCenter(c: Container, p: UserPrincipal) {
  const account = await c.auth.account(p);
  const passkeys = c.auth.passkeysConfigured ? await c.auth.listPasskeys(p) : [];
  const orgs = await c.auth.listOrganizations(p);
  const devices = await c.licensing.myDevices(
    p,
    orgs.map((o) => o.id),
  );
  const recommendations: string[] = [];
  if (!account.emailVerified && account.recoveryConfigured)
    recommendations.push('Verify your email so you can recover your account.');
  if (account.mfaConfigured && !account.mfaEnabled && passkeys.length === 0)
    recommendations.push('Add an authenticator or a passkey: a password alone can be phished.');
  if (c.auth.passkeysConfigured && passkeys.length === 0)
    recommendations.push('Add a passkey for phishing-resistant sign-in.');
  for (const d of devices)
    if (d.posture === 'STEP_UP_AUTH')
      recommendations.push(
        `Sign in again on device ${d.deviceId}: it showed signs of being copied.`,
      );
  return {
    account: {
      email: account.email,
      emailVerified: account.emailVerified,
      authenticatorEnabled: account.mfaEnabled,
      passkeys: passkeys.length,
      operator: account.platformRole === 'platform_admin',
    },
    organizations: orgs.map((o) => ({
      id: o.id,
      name: o.name,
      role: o.role,
      permissions: permissionsFor(o.role).map((permission) => ({
        permission,
        description: PERMISSION_DESCRIPTIONS[permission],
      })),
    })),
    devices,
    dataCategories: DATA_CATEGORIES,
    recommendations,
  };
}
