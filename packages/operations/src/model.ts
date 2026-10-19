import type { UserPrincipal } from '@trust/shared-types';
import type { AuditWriter } from '@trust/audit';

export type InventoryType = 'application' | 'environment' | 'component';
export type InventoryState = 'active' | 'disabled' | 'archived';
export type Criticality = 'low' | 'medium' | 'high' | 'critical';
export type EnvironmentKind = 'development' | 'staging' | 'production';
export type ComponentKind =
  'service' | 'database' | 'storage' | 'worker' | 'scanner' | 'desktop' | 'provider';
interface Base {
  id: string;
  orgId: string;
  code: string;
  state: InventoryState;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}
export interface Application extends Base {
  ownerUserId: string;
  criticality: Criticality;
  productId: string | null;
}
export interface Environment extends Base {
  applicationId: string;
  kind: EnvironmentKind;
}
export interface Component extends Base {
  applicationId: string;
  environmentId: string;
  kind: ComponentKind;
  dependencyIds: string[];
}
export interface InventoryEntities {
  application: Application;
  environment: Environment;
  component: Component;
}
export interface InventoryScope {
  orgId: string;
  applicationId?: string;
  environmentId?: string;
}
export interface CredentialScope {
  orgId: string;
  applicationId: string;
  environmentId: string;
}
export interface CredentialRecord extends CredentialScope {
  id: string;
  purpose: 'events:write';
  source: 'backend_report';
  secretHash: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  rotatedAt: Date | null;
}
export interface CredentialListOptions {
  limit: number;
  after?: string;
  activeAt?: Date;
}
/** All mutation work, including audit, must run inside a serialized organization transaction. */
export interface InventoryRepo {
  findCredential(id: string): Promise<CredentialRecord | undefined>;
  listCredentials(
    scope: CredentialScope,
    options: CredentialListOptions,
  ): Promise<CredentialRecord[]>;
  insertCredential(row: CredentialRecord): Promise<void>;
  /** Identity/digest never change, expiry only shortens, revoke and rotation are irreversible. */
  updateCredential(row: CredentialRecord): Promise<void>;
  find<K extends InventoryType>(
    type: K,
    orgId: string,
    id: string,
  ): Promise<InventoryEntities[K] | undefined>;
  list<K extends InventoryType>(type: K, scope: InventoryScope): Promise<InventoryEntities[K][]>;
  insert<K extends InventoryType>(type: K, row: InventoryEntities[K]): Promise<void>;
  update<K extends InventoryType>(
    type: K,
    row: InventoryEntities[K],
    expectedVersion: number,
  ): Promise<void>;
}
export interface InventoryAuthority {
  authorize(
    p: UserPrincipal,
    orgId: string,
    permission: 'ops:read' | 'ops:manage_inventory' | 'ops:manage_credentials',
  ): Promise<void>;
  assertWritable(orgId: string): Promise<void>;
  sessionActive?(p: UserPrincipal, now: Date): Promise<boolean>;
  activeMember(orgId: string, userId: string): Promise<boolean>;
  activeProduct(productId: string): Promise<boolean>;
}
export interface InventoryTx extends InventoryRepo {
  /** PG adapters bind these checks to the SAME connection to avoid pool exhaustion. */
  authority?: InventoryAuthority;
  audit: AuditWriter;
}
export interface InventoryStore extends InventoryRepo {
  /** Lock organization before ancestor locks; callback may be retried after a deadlock. */
  transaction<T>(orgId: string, fn: (tx: InventoryTx) => Promise<T>): Promise<T>;
}
