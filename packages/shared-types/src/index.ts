// Shared kernel: types and tiny runtime helpers used by every bounded context.
// Keep this package free of business logic and of Node-only dependencies.

export const Decision = {
  ALLOW: 'ALLOW',
  OBSERVE: 'OBSERVE',
  STEP_UP_AUTH: 'STEP_UP_AUTH',
  RESTRICT: 'RESTRICT',
  SUSPEND: 'SUSPEND',
  DENY: 'DENY',
} as const;
export type Decision = (typeof Decision)[keyof typeof Decision];

export interface PolicyOutcome {
  decision: Decision;
  /** Machine-readable reasons. Safe to log; may be shown to the caller only if `exposable`. */
  reasons: string[];
}

export const TIERS = ['trial', 'standard', 'professional', 'business', 'enterprise'] as const;
export type Tier = (typeof TIERS)[number];

export const ORG_ROLES = ['owner', 'admin', 'member'] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

export type PlatformRole = 'none' | 'platform_admin';

/** Authenticated end-user principal, produced only by the auth layer from a verified session. */
export interface UserPrincipal {
  kind: 'user';
  userId: string;
  sessionId: string;
  platformRole: PlatformRole;
}

export interface Clock {
  now(): Date;
}
export const systemClock: Clock = { now: () => new Date() };

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Stable, client-visible error codes. Never change a code's meaning; add new ones. */
export const ERROR_STATUS = {
  invalid_request: 400,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  // Licensing / activation outcomes
  invalid_license: 403,
  license_suspended: 403,
  license_revoked: 403,
  license_expired: 403,
  subscription_inactive: 403,
  device_limit_reached: 409,
  invalid_challenge: 403,
  invalid_device_proof: 403,
  device_key_conflict: 409,
  activation_not_found: 404,
  trial_not_available: 409,
  seat_required: 403,
  seat_limit_reached: 409,
  step_up_required: 403,
  // Sharing outcomes
  quota_exceeded: 409,
  link_unavailable: 410,
  password_required: 401,
  // Privileged operations (ADR-022)
  frozen: 423,
  internal: 500,
} as const;
export type ErrorCode = keyof typeof ERROR_STATUS;

export class DomainError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details: Record<string, Json> | undefined;
  constructor(code: ErrorCode, message: string, details?: Record<string, Json>) {
    super(message);
    this.name = 'DomainError';
    this.code = code;
    this.status = ERROR_STATUS[code];
    this.details = details;
  }
}

export function assertNever(x: never): never {
  throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

export { redact, REDACTED } from './redact.ts';
export * from './lease.ts';
