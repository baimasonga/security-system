import { randomUUID } from 'node:crypto';
import { newId } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type { CredentialScope, InventoryAuthority, InventoryStore, InventoryTx } from './model.ts';
import type { Incident } from './incidents.ts';
import {
  ALERT_EVENTS,
  RUNBOOKS,
  type AlertRule,
  type AlertNotification,
} from './automation-model.ts';
export interface AutomationDependencies {
  store: InventoryStore;
  clock: Clock;
  enabled(): boolean;
  authority: InventoryAuthority;
  /** Fixed portal destination; no provider messages, arbitrary URLs or event attributes. */
  deliver?(notification: Readonly<AlertNotification>): Promise<void>;
}
export type CreateAlertRule = Pick<
  AlertRule,
  'componentId' | 'kind' | 'eventType' | 'threshold' | 'windowSeconds' | 'severity' | 'runbook'
> & { reason: 'initial_setup' };
const missing = () => new DomainError('not_found', 'not found');
const conflict = () => new DomainError('conflict', 'request rejected');
const invalid = () => new DomainError('invalid_request', 'request rejected');
const sameScope = (a: CredentialScope, b: CredentialScope) =>
  a.orgId === b.orgId && a.applicationId === b.applicationId && a.environmentId === b.environmentId;
export class AutomationService {
  readonly #d: AutomationDependencies;
  constructor(d: AutomationDependencies) {
    this.#d = d;
  }
  async #authorized<T>(
    p: UserPrincipal,
    scope: CredentialScope,
    write: boolean,
    fn: (tx: InventoryTx) => Promise<T>,
  ) {
    if (!this.#d.enabled()) throw missing();
    const check = async (authority: InventoryAuthority) => {
      await authority.authorize(p, scope.orgId, write ? 'ops:manage_incidents' : 'ops:read');
      if (!(await authority.sessionActive?.(p, this.#d.clock.now())))
        throw new DomainError('unauthenticated', 'authentication required');
      if (write) await authority.assertWritable(scope.orgId);
    };
    await check(this.#d.authority);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await check(tx.authority ?? this.#d.authority);
      await this.#parents(tx, scope);
      return fn(tx);
    });
  }
  async #parents(tx: InventoryTx, scope: CredentialScope) {
    const a = await tx.find('application', scope.orgId, scope.applicationId),
      e = await tx.find('environment', scope.orgId, scope.environmentId);
    if (!a || !e || e.applicationId !== a.id) throw missing();
    return { a, e };
  }
  async list(p: UserPrincipal, scope: CredentialScope) {
    return this.#authorized(p, scope, false, async (tx) => ({
      items: await tx.listAlertRules(scope),
    }));
  }
  async notifications(p: UserPrincipal, scope: CredentialScope) {
    return this.#authorized(p, scope, false, async (tx) => ({
      items: (await tx.listAlertNotifications(scope, p.userId))
        .filter((n) => n.expiresAt > this.#d.clock.now())
        .map((n) => ({
          id: n.id,
          incidentId: n.incidentId,
          transition: n.transition,
          state: n.state,
          attempts: n.attempts,
          createdAt: n.createdAt,
          deliveredAt: n.deliveredAt,
          deadline: n.deadline,
        })),
    }));
  }
  async create(p: UserPrincipal, scope: CredentialScope, input: CreateAlertRule) {
    if (
      input.reason !== 'initial_setup' ||
      !['event_count', 'heartbeat'].includes(input.kind) ||
      !Number.isInteger(input.threshold) ||
      input.threshold < 1 ||
      input.threshold > 1000 ||
      !Number.isInteger(input.windowSeconds) ||
      input.windowSeconds < 60 ||
      input.windowSeconds > 3600 ||
      !['informational', 'warning', 'critical'].includes(input.severity) ||
      !RUNBOOKS.includes(input.runbook) ||
      (input.kind === 'event_count'
        ? !ALERT_EVENTS.includes(input.eventType as (typeof ALERT_EVENTS)[number])
        : input.eventType !== null || input.threshold !== 1)
    )
      throw invalid();
    return this.#authorized(p, scope, true, async (tx) => {
      const { a, e } = await this.#parents(tx, scope),
        c = await tx.find('component', scope.orgId, input.componentId);
      if (
        !c ||
        !sameScope(
          { ...scope, applicationId: c.applicationId, environmentId: c.environmentId },
          scope,
        )
      )
        throw missing();
      if ([a, e, c].some((r) => r.state !== 'active')) throw conflict();
      if ((await tx.listAlertRules(scope)).length >= 25)
        throw new DomainError('quota_exceeded', 'request rejected');
      const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now());
      const { reason, ...definition } = input;
      const row: AlertRule = {
        ...scope,
        ...definition,
        id: newId('opr'),
        enabled: true,
        maintenanceUntil: null,
        createdByUserId: p.userId,
        version: 1,
        createdAt: now,
        updatedAt: now,
        evaluatedAt: null,
        badSince: null,
        recoverySince: null,
        incidentId: null,
        observation: 'unknown',
        observedCount: 0,
      };
      await tx.insertAlertRule(row);
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: 'operations.rule.created',
        target: { type: 'operations_rule', id: row.id },
        reason,
        metadata: { kind: row.kind, component_id: row.componentId },
      });
      return row;
    });
  }
  async configure(
    p: UserPrincipal,
    scope: CredentialScope,
    id: string,
    input: {
      expectedVersion: number;
      enabled: boolean;
      maintenanceUntil: Date | null;
      reason: 'maintenance' | 'security_response';
    },
  ) {
    if (
      !Number.isInteger(input.expectedVersion) ||
      input.expectedVersion < 1 ||
      typeof input.enabled !== 'boolean' ||
      !['maintenance', 'security_response'].includes(input.reason) ||
      (input.maintenanceUntil !== null &&
        (!Number.isFinite(+input.maintenanceUntil) ||
          input.maintenanceUntil <= this.#d.clock.now() ||
          +input.maintenanceUntil > +this.#d.clock.now() + 7 * 86400000))
    )
      throw invalid();
    return this.#authorized(p, scope, true, async (tx) => {
      const old = await tx.findAlertRule(scope.orgId, id);
      if (!old || !sameScope(old, scope)) throw missing();
      if (old.version !== input.expectedVersion) throw conflict();
      const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now());
      const row = {
        ...old,
        enabled: input.enabled,
        maintenanceUntil: input.maintenanceUntil,
        version: old.version + 1,
        updatedAt: now,
        badSince: null,
        recoverySince: null,
      };
      await tx.updateAlertRule(row, old.version);
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: 'operations.rule.configured',
        target: { type: 'operations_rule', id },
        reason: input.reason,
        metadata: {
          enabled: row.enabled,
          maintenance_until: row.maintenanceUntil?.toISOString() ?? null,
          version: row.version,
        },
      });
      return row;
    });
  }
  /** Internal scheduler entry point. Scope must come from the persisted queue or authorized evaluateNow. */
  async evaluate(scope: CredentialScope, p?: UserPrincipal) {
    if (!this.#d.enabled()) return;
    await this.#d.store.transaction(scope.orgId, async (tx) => {
      if (p) {
        const authority = tx.authority ?? this.#d.authority;
        await authority.authorize(p, scope.orgId, 'ops:manage_incidents');
        if (!(await authority.sessionActive?.(p, this.#d.clock.now())))
          throw new DomainError('unauthenticated', 'authentication required');
        await authority.assertWritable(scope.orgId);
      }
      const { a, e } = await this.#parents(tx, scope);
      const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now());
      for (const old of await tx.listAlertRules(scope)) {
        if (old.evaluatedAt && now < old.evaluatedAt) continue;
        const c = await tx.find('component', scope.orgId, old.componentId);
        const row = { ...old, version: old.version + 1, updatedAt: now, evaluatedAt: now };
        if (!old.enabled || !c || [a, e, c].some((r) => r.state !== 'active')) {
          row.observation = 'inactive';
          row.badSince = null;
          row.recoverySince = null;
          await tx.updateAlertRule(row, old.version);
          continue;
        }
        let incident = old.incidentId
          ? await tx.findIncident(scope.orgId, old.incidentId)
          : undefined;
        const epoch = Math.max(
          +old.createdAt,
          +a.updatedAt,
          +e.updatedAt,
          +c.updatedAt,
          incident?.state === 'resolved' ? +incident.resolvedAt! : 0,
        );
        const hb = await tx.getHeartbeat(scope, c.id);
        const eligible =
          hb &&
          +hb.occurredAt >= epoch &&
          [a, e, c].every((resource) =>
            resource.version === 1
              ? hb.occurredAt >= resource.updatedAt
              : hb.occurredAt > resource.updatedAt,
          ) &&
          hb.receivedAt <= now &&
          hb.expiresAt > now &&
          hb.occurredAt <= now
            ? hb
            : undefined;
        const fresh = eligible && +now - +eligible.receivedAt < 180000;
        row.observedCount =
          old.kind === 'event_count'
            ? await tx.countAlertEvents(
                scope,
                c.id,
                old.eventType!,
                new Date(Math.max(epoch, +now - old.windowSeconds * 1000)),
                now,
                old.threshold,
              )
            : 0;
        const bad =
          old.kind === 'event_count'
            ? row.observedCount >= old.threshold
            : !!eligible && (!fresh || ['unavailable', 'degraded'].includes(eligible.status));
        const healthy = !!fresh && eligible.status === 'healthy' && !bad;
        row.observation = bad ? 'breaching' : healthy ? 'healthy' : 'unknown';
        row.badSince = bad ? (old.badSince ?? now) : null;
        row.recoverySince = healthy ? (old.recoverySince ?? now) : null;
        const qualifies =
          bad && (old.kind === 'event_count' || +now - +row.badSince! >= old.windowSeconds * 1000);
        if (qualifies && (!incident || incident.state === 'resolved')) {
          const retained = await tx.listIncidents(scope, { limit: 1001 });
          if (retained.length >= 1000) throw new DomainError('quota_exceeded', 'request rejected');
          incident = {
            ...scope,
            id: newId('opi'),
            componentId: c.id,
            source: 'automatic_rule',
            ruleId: old.id,
            severity: old.severity,
            state: 'open',
            assigneeUserId: null,
            createdByUserId: old.createdByUserId,
            version: 1,
            createdAt: now,
            updatedAt: now,
            acknowledgedAt: null,
            resolvedAt: null,
          };
          await tx.insertIncident(incident);
          row.incidentId = incident.id;
          row.recoverySince = null;
          await this.#transition(tx, row, incident, 'opened', now);
        } else if (
          incident &&
          incident.state !== 'resolved' &&
          healthy &&
          eligible!.occurredAt > incident.createdAt &&
          row.recoverySince &&
          +now - +row.recoverySince >= old.windowSeconds * 1000
        ) {
          const resolved = {
            ...incident,
            state: 'resolved' as const,
            version: incident.version + 1,
            updatedAt: now,
            resolvedAt: now,
          };
          await tx.updateIncident(resolved, incident.version);
          await this.#transition(tx, row, resolved, 'resolved', now);
        }
        await tx.updateAlertRule(row, old.version);
      }
      await tx.pruneAutomation(scope.orgId, now, 100);
    });
  }
  async #transition(
    tx: InventoryTx,
    rule: AlertRule,
    incident: Incident,
    transition: 'opened' | 'resolved',
    now: Date,
  ) {
    await tx.audit.append({
      actor: { type: 'system' },
      orgId: rule.orgId,
      action: `operations.incident.${transition}`,
      target: { type: 'operations_incident', id: incident.id },
      reason: 'automatic_rule',
      metadata: {
        rule_id: rule.id,
        component_id: rule.componentId,
        severity: rule.severity,
        runbook: rule.runbook,
        notification_suppressed: !!rule.maintenanceUntil && rule.maintenanceUntil > now,
      },
    });
    if (rule.maintenanceUntil && rule.maintenanceUntil > now) return;
    const authority = tx.authority ?? this.#d.authority;
    if (!(await authority.activeMember(rule.orgId, rule.createdByUserId))) return;
    if ((await tx.listAlertNotifications(rule)).length >= 2000)
      throw new DomainError('quota_exceeded', 'request rejected');
    await tx.insertAlertNotification({
      orgId: rule.orgId,
      applicationId: rule.applicationId,
      environmentId: rule.environmentId,
      id: newId('opn'),
      incidentId: incident.id,
      recipientUserId: rule.createdByUserId,
      transition,
      state: 'pending',
      attempts: 0,
      createdAt: now,
      availableAt: now,
      deadline: new Date(+now + 72 * 3600000),
      expiresAt: new Date(+now + 30 * 86400000),
      claimToken: null,
      leaseUntil: null,
      deliveredAt: null,
    });
  }
  async evaluateNow(p: UserPrincipal, scope: CredentialScope) {
    await this.evaluate(scope, p);
    return this.list(p, scope);
  }
  async deliverPending(scope: CredentialScope) {
    if (!this.#d.enabled()) return;
    for (let i = 0; i < 25; i++) {
      const claimed = await this.#d.store.transaction(scope.orgId, async (tx) => {
        const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now());
        const rows = await tx.listAlertNotifications(scope);
        const n = rows.find(
          (r) =>
            (r.state === 'pending' && r.availableAt <= now) ||
            (r.state === 'claimed' && r.leaseUntil! <= now),
        );
        if (!n) return;
        if (
          n.deadline <= now ||
          !(await (tx.authority ?? this.#d.authority).activeMember(scope.orgId, n.recipientUserId))
        ) {
          await tx.updateAlertNotification({
            ...n,
            state: 'failed',
            claimToken: null,
            leaseUntil: null,
          });
          return null;
        }
        const row = {
          ...n,
          state: 'claimed' as const,
          attempts: n.attempts + 1,
          claimToken: randomUUID(),
          leaseUntil: new Date(+now + 30000),
        };
        await tx.updateAlertNotification(row);
        return row;
      });
      if (claimed === undefined) break;
      if (!claimed) continue;
      let ok = false;
      try {
        await this.#d.deliver?.(claimed);
        ok = true;
      } catch {
        /* Never retain provider payloads or errors. */
      }
      await this.#d.store.transaction(scope.orgId, async (tx) => {
        const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now()),
          current = await tx.findAlertNotification(scope.orgId, claimed.id);
        if (
          !current ||
          current.state !== 'claimed' ||
          current.claimToken !== claimed.claimToken ||
          current.leaseUntil! <= now
        )
          return;
        await tx.updateAlertNotification({
          ...current,
          state: ok ? 'delivered' : now >= current.deadline ? 'failed' : 'pending',
          availableAt: new Date(+now + Math.min(300, 2 ** Math.min(9, current.attempts)) * 1000),
          claimToken: null,
          leaseUntil: null,
          deliveredAt: ok ? now : null,
        });
      });
    }
  }
  async tick() {
    if (!this.#d.enabled()) return;
    let failed = false;
    for (const scope of await this.#d.store.automationScopes(this.#d.clock.now(), 25)) {
      try {
        await this.evaluate(scope);
      } catch {
        failed = true;
      }
      try {
        await this.deliverPending(scope);
      } catch {
        failed = true;
      }
    }
    if (failed) throw new Error('operations batch incomplete');
  }
}
