import type { Tier } from './index.ts';

/** Wire contract for offline leases (see ADR-002). Shared by the server and every SDK. */
export const LEASE_TYP = 'lease+jws';
export const LEASE_SCHEMA_VERSION = 1;

export interface LeaseClaims {
  v: 1;
  /** Lease id. */
  jti: string;
  /** Issuer. */
  iss: string;
  /** Audience: `product:<product code>`. A lease for one product never validates for another. */
  aud: string;
  lic: string;
  org: string;
  prd: string;
  pln: string;
  /** Plan version snapshot. */
  plv: number;
  act: string;
  inst: string;
  dev: string;
  /** Confirmation: thumbprint of the device key this lease is bound to. */
  cnf: { jkt: string };
  kind: 'subscription' | 'trial' | 'perpetual';
  tier: Tier;
  ent: Record<string, boolean | number>;
  cap: string[];
  /** Device limit at issue time (informational). */
  dl: number;
  /** Seconds since epoch. */
  iat: number;
  nbf: number;
  /** Client should refresh when online after this time. */
  refresh_after: number;
  /** Hard offline expiry. */
  exp: number;
}

export const audienceForProduct = (productCode: string): string => `product:${productCode}`;
