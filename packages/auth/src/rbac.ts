import type { OrgRole } from '@trust/shared-types';

export const PERMISSIONS = [
  'org:read',
  'org:manage_members',
  'license:read',
  'license:activate',
  'license:manage_seats',
  'trial:start',
  'device:read',
  'device:deactivate',
  'share:read',
  'share:create',
  'share:manage',
  'ops:read',
  'ops:manage_inventory',
  'ops:manage_credentials',
  'ops:manage_incidents',
  'ops:manage_security',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

// Deny by default: a permission not listed for a role is not granted.
const GRANTS: Record<OrgRole, readonly Permission[]> = {
  member: [
    'org:read',
    'license:read',
    'license:activate',
    'trial:start',
    'device:read',
    'share:read',
    'share:create',
  ],
  admin: [
    'org:read',
    'org:manage_members',
    'license:read',
    'license:activate',
    'license:manage_seats',
    'trial:start',
    'device:read',
    'device:deactivate',
    'share:read',
    'share:create',
    'share:manage',
    'ops:read',
    'ops:manage_inventory',
    'ops:manage_credentials',
    'ops:manage_incidents',
    'ops:manage_security',
  ],
  owner: [
    'org:read',
    'org:manage_members',
    'license:read',
    'license:activate',
    'license:manage_seats',
    'trial:start',
    'device:read',
    'device:deactivate',
    'share:read',
    'share:create',
    'share:manage',
    'ops:read',
    'ops:manage_inventory',
    'ops:manage_credentials',
    'ops:manage_incidents',
    'ops:manage_security',
  ],
};

/** Plain-language meaning of each permission, shown in the security center (ADR-027). */
export const PERMISSION_DESCRIPTIONS: Record<Permission, string> = {
  'ops:manage_security': 'Import security/recovery reports and triage findings',
  'ops:manage_incidents': 'Open, assign, acknowledge and resolve operational incidents',
  'ops:manage_credentials':
    'Issue, rotate and revoke application integration credentials with fresh MFA',
  'ops:read': 'See application monitoring inventory and evidence',
  'ops:manage_inventory': 'Manage application, environment and component inventory',
  'org:read': 'See the organization, its members and their roles',
  'org:manage_members': 'Add members and set their roles',
  'license:read': 'See licenses, entitlements, usage and seats',
  'license:activate': 'Activate licenses on your devices',
  'license:manage_seats': 'Give and remove seats on seat-based licenses',
  'trial:start': 'Start a product trial for the organization',
  'device:read': 'See activated devices, their passports and trust posture',
  'device:deactivate': "Sign out anyone's device to free a slot",
  'share:read': 'See shared files, documents and links',
  'share:create': 'Upload files and create share links',
  'share:manage': 'Manage, hold or delete any shared item in the organization',
};

export function permissionsFor(role: OrgRole): readonly Permission[] {
  return GRANTS[role];
}

export function roleAllows(role: OrgRole, permission: Permission): boolean {
  return GRANTS[role].includes(permission);
}

const RANK: Record<OrgRole, number> = { member: 1, admin: 2, owner: 3 };
/** An actor may grant at most their own rank; only owners create owners. */
export function canGrantRole(actor: OrgRole, target: OrgRole): boolean {
  return RANK[actor] >= RANK[target] && (target !== 'owner' || actor === 'owner');
}
