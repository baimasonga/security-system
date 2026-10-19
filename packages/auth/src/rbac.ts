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
  ],
};

export function roleAllows(role: OrgRole, permission: Permission): boolean {
  return GRANTS[role].includes(permission);
}

const RANK: Record<OrgRole, number> = { member: 1, admin: 2, owner: 3 };
/** An actor may grant at most their own rank; only owners create owners. */
export function canGrantRole(actor: OrgRole, target: OrgRole): boolean {
  return RANK[actor] >= RANK[target] && (target !== 'owner' || actor === 'owner');
}
