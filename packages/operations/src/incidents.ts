import { newId } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type { CredentialScope, InventoryAuthority, InventoryStore, InventoryTx } from './model.ts';

export type IncidentState = 'open' | 'acknowledged' | 'resolved';
export type IncidentSeverity = 'informational' | 'warning' | 'critical';
export interface Incident extends CredentialScope {
  id: string;
  componentId: string;
  source: 'manual_triage';
  severity: IncidentSeverity;
  state: IncidentState;
  assigneeUserId: string | null;
  createdByUserId: string;
  version: number;
  createdAt: Date;
  updatedAt: Date;
  acknowledgedAt: Date | null;
  resolvedAt: Date | null;
}
export interface IncidentRepo {
  findIncident(orgId: string, id: string): Promise<Incident | undefined>;
  listIncidents(
    scope: CredentialScope,
    options: { limit: number; after?: string },
  ): Promise<Incident[]>;
  insertIncident(row: Incident): Promise<void>;
  updateIncident(row: Incident, expectedVersion: number): Promise<void>;
}
export interface IncidentDependencies {
  store: InventoryStore;
  clock: Clock;
  enabled(): boolean;
  authority: InventoryAuthority;
}
const missing = () => new DomainError('not_found', 'not found');
const conflict = () => new DomainError('conflict', 'request rejected');
const invalid = () => new DomainError('invalid_request', 'request rejected');

/** Human triage only. Does not claim a backend observation or deliver external alerts. */
export class IncidentService {
  readonly #d: IncidentDependencies;
  constructor(d: IncidentDependencies) {
    this.#d = d;
  }
  async #authorize(
    p: UserPrincipal,
    scope: CredentialScope,
    write: boolean,
    authority: InventoryAuthority,
  ) {
    await authority.authorize(p, scope.orgId, write ? 'ops:manage_incidents' : 'ops:read');
    if (!(await authority.sessionActive?.(p, this.#d.clock.now())))
      throw new DomainError('unauthenticated', 'authentication required');
    if (write) {
      try {
        await authority.assertWritable(scope.orgId);
      } catch (e) {
        if (e instanceof DomainError && e.code === 'frozen')
          throw new DomainError('forbidden', 'request rejected');
        throw e;
      }
    }
  }
  async #run<T>(
    p: UserPrincipal,
    scope: CredentialScope,
    write: boolean,
    fn: (tx: InventoryTx, authority: InventoryAuthority) => Promise<T>,
  ) {
    if (!this.#d.enabled()) throw missing();
    await this.#authorize(p, scope, write, this.#d.authority);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      const authority = tx.authority ?? this.#d.authority;
      await this.#authorize(p, scope, write, authority);
      const a = await tx.find('application', scope.orgId, scope.applicationId);
      const e = await tx.find('environment', scope.orgId, scope.environmentId);
      if (!a || !e || e.applicationId !== a.id) throw missing();
      return fn(tx, authority);
    });
  }
  async list(p: UserPrincipal, scope: CredentialScope, options: { limit: number; after?: string }) {
    if (
      !Number.isInteger(options.limit) ||
      options.limit < 1 ||
      options.limit > 100 ||
      (options.after !== undefined && !/^opi_[a-f0-9]{24}$/.test(options.after))
    )
      throw invalid();
    return this.#run(p, scope, false, async (tx) => {
      const rows = await tx.listIncidents(scope, { ...options, limit: options.limit + 1 });
      return {
        items: rows.slice(0, options.limit),
        nextAfter: rows.length > options.limit ? rows[options.limit - 1]!.id : null,
      };
    });
  }
  async open(
    p: UserPrincipal,
    scope: CredentialScope,
    input: { componentId: string; severity: IncidentSeverity; reason: 'security_response' },
  ) {
    if (
      input.reason !== 'security_response' ||
      !['informational', 'warning', 'critical'].includes(input.severity)
    )
      throw invalid();
    return this.#run(p, scope, true, async (tx) => {
      const a = (await tx.find('application', scope.orgId, scope.applicationId))!;
      const e = (await tx.find('environment', scope.orgId, scope.environmentId))!;
      const c = await tx.find('component', scope.orgId, input.componentId);
      if (!c || c.applicationId !== a.id || c.environmentId !== e.id) throw missing();
      if ([a, e, c].some((r) => r.state !== 'active')) throw conflict();
      const rows = await tx.listIncidents(scope, { limit: 1001 });
      const active = rows.find((r) => r.componentId === c.id && r.state !== 'resolved');
      if (active) return { incident: active, created: false };
      if (rows.length >= 1000) throw new DomainError('quota_exceeded', 'request rejected');
      const now = this.#d.clock.now();
      const row: Incident = {
        ...scope,
        id: newId('opi'),
        componentId: c.id,
        source: 'manual_triage',
        severity: input.severity,
        state: 'open',
        assigneeUserId: null,
        createdByUserId: p.userId,
        version: 1,
        createdAt: now,
        updatedAt: now,
        acknowledgedAt: null,
        resolvedAt: null,
      };
      await tx.insertIncident(row);
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: 'operations.incident.opened',
        target: { type: 'operations_incident', id: row.id },
        reason: input.reason,
        metadata: { component_id: c.id, source: row.source, severity: row.severity },
      });
      return { incident: row, created: true };
    });
  }
  async act(
    p: UserPrincipal,
    scope: CredentialScope,
    id: string,
    input:
      | { action: 'acknowledge'; expectedVersion: number; reason: 'incident_ack' }
      | { action: 'resolve'; expectedVersion: number; reason: 'incident_resolution' }
      | {
          action: 'assign';
          expectedVersion: number;
          reason: 'assignment';
          assigneeUserId: string | null;
        },
  ) {
    const reasons = {
      acknowledge: 'incident_ack',
      resolve: 'incident_resolution',
      assign: 'assignment',
    };
    if (
      !['acknowledge', 'resolve', 'assign'].includes(input.action) ||
      !Number.isInteger(input.expectedVersion) ||
      input.expectedVersion < 1 ||
      reasons[input.action] !== input.reason
    )
      throw invalid();
    return this.#run(p, scope, true, async (tx, authority) => {
      const old = await tx.findIncident(scope.orgId, id);
      if (
        !old ||
        old.applicationId !== scope.applicationId ||
        old.environmentId !== scope.environmentId
      )
        throw missing();
      if (
        old.state === 'resolved' ||
        old.version !== input.expectedVersion ||
        (input.action === 'acknowledge' && old.state !== 'open')
      )
        throw conflict();
      const now = new Date(Math.max(+old.updatedAt, +this.#d.clock.now()));
      const row = { ...old, version: old.version + 1, updatedAt: now };
      if (input.action === 'assign') {
        if (
          input.assigneeUserId !== null &&
          (!/^usr_[a-f0-9]{24}$/.test(input.assigneeUserId) ||
            !(await authority.activeMember(scope.orgId, input.assigneeUserId)))
        )
          throw missing();
        row.assigneeUserId = input.assigneeUserId;
      } else if (input.action === 'acknowledge') {
        row.state = 'acknowledged';
        row.acknowledgedAt = now;
      } else {
        row.state = 'resolved';
        row.resolvedAt = now;
      }
      await tx.updateIncident(row, old.version);
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: `operations.incident.${input.action === 'assign' ? 'assigned' : input.action === 'resolve' ? 'resolved' : 'acknowledged'}`,
        target: { type: 'operations_incident', id: row.id },
        reason: input.reason,
        metadata: {
          version: row.version,
          from_state: old.state,
          to_state: row.state,
          ...(input.action === 'assign'
            ? { from_assignee_user_id: old.assigneeUserId, to_assignee_user_id: row.assigneeUserId }
            : {}),
        },
      });
      return row;
    });
  }
}
