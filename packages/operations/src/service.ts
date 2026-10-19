import { contentViolation } from '@trust/telemetry';
import { newId } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type {
  Application,
  Component,
  ComponentKind,
  Criticality,
  Environment,
  EnvironmentKind,
  InventoryAuthority,
  InventoryEntities,
  InventoryScope,
  InventoryState,
  InventoryStore,
  InventoryTx,
  InventoryType,
} from './model.ts';

export const INVENTORY_REASONS = [
  'initial_setup',
  'owner_transfer',
  'maintenance',
  'retirement',
  'restore',
  'security_response',
  'routine_rotation',
  'config_change',
  'incident_ack',
  'incident_resolution',
  'assignment',
] as const;
export type InventoryReason = (typeof INVENTORY_REASONS)[number];
export interface InventoryDependencies {
  store: InventoryStore;
  clock: Clock;
  authorize(
    p: UserPrincipal,
    orgId: string,
    permission: 'ops:read' | 'ops:manage_inventory',
  ): Promise<void>;
  assertWritable(orgId: string): Promise<void>;
  activeMember(orgId: string, userId: string): Promise<boolean>;
  activeProduct(productId: string): Promise<boolean>;
}
export interface CreateApplication {
  code: string;
  ownerUserId: string;
  criticality: Criticality;
  productId: string | null;
  reason: InventoryReason;
}
export interface CreateEnvironment {
  code: string;
  kind: EnvironmentKind;
  reason: InventoryReason;
}
export interface CreateComponent {
  code: string;
  kind: ComponentKind;
  dependencyIds: string[];
  reason: InventoryReason;
}
export interface UpdateInventory {
  expectedVersion: number;
  reason: InventoryReason;
  state?: InventoryState;
  ownerUserId?: string;
  criticality?: Criticality;
  productId?: string | null;
  kind?: EnvironmentKind | ComponentKind;
  dependencyIds?: string[];
}
const missing = () => new DomainError('not_found', 'not found');
const conflict = () => new DomainError('conflict', 'request rejected');
const invalid = () => new DomainError('invalid_request', 'request rejected');

export class InventoryService {
  readonly #d: InventoryDependencies;
  constructor(d: InventoryDependencies) {
    this.#d = d;
  }
  async #authorize(
    p: UserPrincipal,
    orgId: string,
    write: boolean,
    authority: InventoryAuthority = this.#d,
  ) {
    await authority.authorize(p, orgId, write ? 'ops:manage_inventory' : 'ops:read');
    if (write) {
      try {
        await authority.assertWritable(orgId);
      } catch (e) {
        if (e instanceof DomainError && e.code === 'frozen')
          throw new DomainError('forbidden', 'request rejected');
        throw e;
      }
    }
  }
  async #parents(tx: InventoryTx | InventoryStore, scope: InventoryScope, write: boolean) {
    if (scope.applicationId) {
      const app = await tx.find('application', scope.orgId, scope.applicationId);
      if (!app) throw missing();
      if (write && app.state !== 'active') throw conflict();
    }
    if (scope.environmentId) {
      const env = await tx.find('environment', scope.orgId, scope.environmentId);
      if (!env || env.applicationId !== scope.applicationId) throw missing();
      if (write && env.state !== 'active') throw conflict();
    }
  }
  async #row<K extends InventoryType>(
    tx: InventoryTx | InventoryStore,
    type: K,
    scope: InventoryScope,
    id: string,
  ) {
    await this.#parents(tx, scope, false);
    const row = await tx.find(type, scope.orgId, id);
    if (
      !row ||
      ('applicationId' in row && row.applicationId !== scope.applicationId) ||
      ('environmentId' in row && row.environmentId !== scope.environmentId)
    )
      throw missing();
    return row;
  }
  async get<K extends InventoryType>(
    p: UserPrincipal,
    type: K,
    scope: InventoryScope,
    id: string,
  ): Promise<InventoryEntities[K]> {
    await this.#authorize(p, scope.orgId, false);
    return this.#row(this.#d.store, type, scope, id);
  }
  async list<K extends InventoryType>(
    p: UserPrincipal,
    type: K,
    scope: InventoryScope,
    options: { limit?: number; cursor?: string } = {},
  ) {
    await this.#authorize(p, scope.orgId, false);
    await this.#parents(this.#d.store, scope, false);
    const limit = options.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw invalid();
    let after: string | undefined;
    if (options.cursor) {
      try {
        if (options.cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(options.cursor))
          throw invalid();
        const decoded = Buffer.from(options.cursor, 'base64url').toString('utf8');
        const cursor = JSON.parse(decoded) as { scope?: string; id?: string };
        if (
          cursor.scope !==
            JSON.stringify([
              type,
              scope.orgId,
              scope.applicationId ?? null,
              scope.environmentId ?? null,
            ]) ||
          typeof cursor.id !== 'string'
        )
          throw invalid();
        await this.#row(this.#d.store, type, scope, cursor.id);
        after = cursor.id;
      } catch {
        throw invalid();
      }
    }
    const rows = (await this.#d.store.list(type, scope)).filter(
      (r) => r.state !== 'archived' && (!after || r.id > after),
    );
    const items = rows.slice(0, limit);
    const nextCursor =
      rows.length > limit
        ? Buffer.from(
            JSON.stringify({
              scope: JSON.stringify([
                type,
                scope.orgId,
                scope.applicationId ?? null,
                scope.environmentId ?? null,
              ]),
              id: items.at(-1)!.id,
            }),
          ).toString('base64url')
        : null;
    return { items, nextCursor };
  }
  async #owner(
    orgId: string,
    userId: string,
    productId: string | null,
    authority: InventoryAuthority = this.#d,
  ) {
    if (!(await authority.activeMember(orgId, userId))) throw missing();
    if (productId && !(await authority.activeProduct(productId))) throw missing();
  }
  async #graph(tx: InventoryTx, orgId: string, id: string, deps: string[]) {
    if (deps.length > 100 || new Set(deps).size !== deps.length) throw invalid();
    const seen = new Set<string>();
    const visit = async (next: string): Promise<void> => {
      if (next === id) throw conflict();
      if (seen.has(next)) return;
      seen.add(next);
      const row = await tx.find('component', orgId, next);
      if (!row) throw missing();
      // Iterative expansion is bounded by the inventory caps; no request URL is ever executed.
      for (const dep of row.dependencyIds) await visit(dep);
    };
    for (const dep of deps) await visit(dep);
  }
  #reason(reason: InventoryReason) {
    if (!INVENTORY_REASONS.includes(reason)) throw invalid();
  }
  async #audit(
    tx: InventoryTx,
    p: UserPrincipal,
    type: InventoryType,
    row: Application | Environment | Component,
    action: string,
    reason: InventoryReason,
  ) {
    await tx.audit.append({
      actor: { type: 'user', id: p.userId },
      orgId: row.orgId,
      action: `operations.${type}.${action}`,
      target: { type: `operations_${type}`, id: row.id },
      reason,
      metadata: { version: row.version, state: row.state },
    });
  }
  async createApplication(
    p: UserPrincipal,
    orgId: string,
    input: CreateApplication,
  ): Promise<Application> {
    return this.#create(p, 'application', { orgId }, input) as Promise<Application>;
  }
  async createEnvironment(
    p: UserPrincipal,
    scope: InventoryScope & { applicationId: string },
    input: CreateEnvironment,
  ): Promise<Environment> {
    return this.#create(p, 'environment', scope, input) as Promise<Environment>;
  }
  async createComponent(
    p: UserPrincipal,
    scope: InventoryScope & { applicationId: string; environmentId: string },
    input: CreateComponent,
  ): Promise<Component> {
    return this.#create(p, 'component', scope, input) as Promise<Component>;
  }
  async #create(
    p: UserPrincipal,
    type: InventoryType,
    scope: InventoryScope,
    input: CreateApplication | CreateEnvironment | CreateComponent,
  ) {
    await this.#authorize(p, scope.orgId, true);
    this.#reason(input.reason);
    if (!/^[a-z][a-z0-9-]{1,47}$/.test(input.code) || contentViolation(input.code)) throw invalid();
    try {
      return await this.#d.store.transaction(scope.orgId, async (tx) => {
        await this.#authorize(p, scope.orgId, true, tx.authority);
        await this.#parents(tx, scope, true);
        const existing = await tx.list(type, scope);
        if (
          existing.length >= { application: 100, environment: 20, component: 100 }[type] ||
          existing.some((r) => r.code === input.code)
        )
          throw conflict();
        const now = this.#d.clock.now();
        const base = {
          id: newId({ application: 'opa', environment: 'ope', component: 'opm' }[type]),
          orgId: scope.orgId,
          code: input.code,
          state: 'active' as const,
          version: 1,
          createdAt: now,
          updatedAt: now,
        };
        let row: Application | Environment | Component;
        if ('ownerUserId' in input) {
          await this.#owner(scope.orgId, input.ownerUserId, input.productId, tx.authority);
          row = {
            ...base,
            ownerUserId: input.ownerUserId,
            criticality: input.criticality,
            productId: input.productId,
          };
        } else if ('dependencyIds' in input) {
          await this.#graph(tx, scope.orgId, base.id, input.dependencyIds);
          row = {
            ...base,
            applicationId: scope.applicationId!,
            environmentId: scope.environmentId!,
            kind: input.kind,
            dependencyIds: [...input.dependencyIds],
          };
        } else row = { ...base, applicationId: scope.applicationId!, kind: input.kind };
        await tx.insert(type, row);
        await this.#audit(tx, p, type, row, 'created', input.reason);
        return row;
      });
    } catch (e) {
      if (e instanceof Error && e.message === 'duplicate_inventory') throw conflict();
      throw e;
    }
  }
  async update<K extends InventoryType>(
    p: UserPrincipal,
    type: K,
    scope: InventoryScope,
    id: string,
    input: UpdateInventory,
  ): Promise<InventoryEntities[K]> {
    await this.#authorize(p, scope.orgId, true);
    this.#reason(input.reason);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await this.#authorize(p, scope.orgId, true, tx.authority);
      const old = await this.#row(tx, type, scope, id);
      await this.#parents(tx, scope, true);
      if (
        old.state === 'archived' ||
        old.version !== input.expectedVersion ||
        old.version >= Number.MAX_SAFE_INTEGER
      )
        throw conflict();
      const row = {
        ...old,
        state: input.state ?? old.state,
        version: old.version + 1,
        updatedAt: this.#d.clock.now(),
      };
      if (type === 'application') {
        const app = row as Application;
        app.ownerUserId = input.ownerUserId ?? app.ownerUserId;
        app.criticality = input.criticality ?? app.criticality;
        if (input.productId !== undefined) app.productId = input.productId;
        await this.#owner(scope.orgId, app.ownerUserId, app.productId, tx.authority);
      } else if (type === 'component') {
        const component = row as Component;
        if (input.kind) component.kind = input.kind as ComponentKind;
        if (input.dependencyIds) {
          await this.#graph(tx, scope.orgId, id, input.dependencyIds);
          component.dependencyIds = [...input.dependencyIds];
        }
      }
      await tx.update(type, row, input.expectedVersion);
      await this.#audit(
        tx,
        p,
        type,
        row,
        row.state === 'archived' ? 'archived' : 'updated',
        input.reason,
      );
      return row;
    });
  }
}
