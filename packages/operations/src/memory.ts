import type { AlertRule, AlertNotification } from './automation-model.ts';
import type { Heartbeat } from './health.ts';
import type { Incident } from './incidents.ts';
import type { OperationEvent } from './events-model.ts';
import { MemoryPostureRepo } from './posture-memory.ts';
import { AuditBuffer, type AuditLog, type AuditEventInput } from '@trust/audit';
import type {
  CredentialRecord,
  CredentialScope,
  CredentialListOptions,
  InventoryEntities,
  InventoryRepo,
  InventoryScope,
  InventoryStore,
  InventoryTx,
  InventoryType,
} from './model.ts';

class Repo extends MemoryPostureRepo implements InventoryRepo {
  rules = new Map<string, AlertRule>();
  notifications = new Map<string, AlertNotification>();
  async listAlertRules(scope: CredentialScope) {
    return [...this.rules.values()]
      .filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId,
      )
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((r) => structuredClone(r));
  }
  async findAlertRule(orgId: string, id: string) {
    const r = this.rules.get(id);
    return r?.orgId === orgId ? structuredClone(r) : undefined;
  }
  async insertAlertRule(row: AlertRule) {
    const c = await this.find('component', row.orgId, row.componentId);
    if (
      !c ||
      c.applicationId !== row.applicationId ||
      c.environmentId !== row.environmentId ||
      this.rules.has(row.id) ||
      row.version !== 1
    )
      throw new Error('rule_invalid');
    this.rules.set(row.id, structuredClone(row));
  }
  async updateAlertRule(row: AlertRule, expectedVersion: number) {
    const old = await this.findAlertRule(row.orgId, row.id);
    if (
      !old ||
      old.version !== expectedVersion ||
      row.version !== old.version + 1 ||
      row.updatedAt < old.updatedAt
    )
      throw new Error('rule_version');
    for (const k of [
      'orgId',
      'applicationId',
      'environmentId',
      'componentId',
      'kind',
      'eventType',
      'threshold',
      'windowSeconds',
      'severity',
      'runbook',
      'createdByUserId',
    ] as const)
      if (row[k] !== old[k]) throw new Error('rule_immutable');
    if (
      +row.createdAt !== +old.createdAt ||
      (old.evaluatedAt && (!row.evaluatedAt || row.evaluatedAt < old.evaluatedAt))
    )
      throw new Error('rule_immutable');
    this.rules.set(row.id, structuredClone(row));
  }
  async automationScopes(now: Date, limit: number) {
    const rows = new Map<string, { scope: CredentialScope; time: number }>();
    const add = (r: CredentialScope, time: number) => {
      const key = JSON.stringify([r.orgId, r.applicationId, r.environmentId]);
      const old = rows.get(key);
      if (!old || time < old.time)
        rows.set(key, {
          scope: { orgId: r.orgId, applicationId: r.applicationId, environmentId: r.environmentId },
          time,
        });
    };
    for (const r of this.rules.values()) add(r, +(r.evaluatedAt ?? new Date(0)));
    for (const n of this.notifications.values())
      if (
        (n.state === 'pending' && n.availableAt <= now) ||
        (n.state === 'claimed' && n.leaseUntil! <= now) ||
        n.expiresAt <= now
      )
        add(n, +n.availableAt);
    for (const r of this.incidents.values())
      if (r.state === 'resolved' && r.resolvedAt && +r.resolvedAt <= +now - 365 * 86400000)
        add(r, +r.resolvedAt);
    return [...rows.values()]
      .sort((a, b) => a.time - b.time)
      .slice(0, limit)
      .map((r) => r.scope);
  }
  async countAlertEvents(
    scope: CredentialScope,
    componentId: string,
    type: string,
    from: Date,
    to: Date,
    cap: number,
  ) {
    return Math.min(
      cap,
      [...this.events.values()].filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId &&
          r.componentId === componentId &&
          r.type === type &&
          r.receivedAt > from &&
          r.receivedAt <= to &&
          r.expiresAt > to,
      ).length,
    );
  }
  async listAlertNotifications(scope: CredentialScope, recipientUserId?: string) {
    return [...this.notifications.values()]
      .filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId &&
          (!recipientUserId || r.recipientUserId === recipientUserId),
      )
      .sort((a, b) => +a.createdAt - +b.createdAt || a.id.localeCompare(b.id))
      .slice(0, 2000)
      .map((r) => structuredClone(r));
  }
  async findAlertNotification(orgId: string, id: string) {
    const r = this.notifications.get(id);
    return r?.orgId === orgId ? structuredClone(r) : undefined;
  }
  async insertAlertNotification(row: AlertNotification) {
    const incident = await this.findIncident(row.orgId, row.incidentId);
    if (
      !incident ||
      incident.applicationId !== row.applicationId ||
      incident.environmentId !== row.environmentId ||
      this.notifications.has(row.id) ||
      [...this.notifications.values()].some(
        (r) =>
          r.incidentId === row.incidentId &&
          r.transition === row.transition &&
          r.recipientUserId === row.recipientUserId,
      )
    )
      throw new Error('notification_invalid');
    this.notifications.set(row.id, structuredClone(row));
  }
  async updateAlertNotification(row: AlertNotification) {
    const old = await this.findAlertNotification(row.orgId, row.id);
    if (!old || ['delivered', 'failed'].includes(old.state) || row.attempts < old.attempts)
      throw new Error('notification_invalid');
    for (const k of [
      'incidentId',
      'recipientUserId',
      'transition',
      'applicationId',
      'environmentId',
    ] as const)
      if (row[k] !== old[k]) throw new Error('notification_immutable');
    this.notifications.set(row.id, structuredClone(row));
  }
  async pruneAutomation(orgId: string, now: Date, limit: number) {
    let notifications = 0,
      incidents = 0;
    for (const r of this.notifications.values())
      if (notifications < limit && r.orgId === orgId && r.expiresAt <= now) {
        this.notifications.delete(r.id);
        notifications++;
      }
    for (const r of this.incidents.values())
      if (
        incidents < limit &&
        r.orgId === orgId &&
        r.resolvedAt &&
        +r.resolvedAt <= +now - 365 * 86400000 &&
        ![...this.notifications.values()].some((n) => n.incidentId === r.id)
      ) {
        this.incidents.delete(r.id);

        incidents++;
      }
    return { notifications, incidents };
  }
  incidents = new Map<string, Incident>();
  async findIncident(orgId: string, id: string) {
    const row = this.incidents.get(id);
    return row?.orgId === orgId ? structuredClone(row) : undefined;
  }
  async listIncidents(scope: CredentialScope, options: { limit: number; after?: string }) {
    return [...this.incidents.values()]
      .filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId &&
          (!options.after || r.id > options.after),
      )
      .sort((a, b) => (a.id < b.id ? -1 : 1))
      .slice(0, options.limit)
      .map((r) => structuredClone(r));
  }
  async insertIncident(row: Incident) {
    const c = await this.find('component', row.orgId, row.componentId);
    if (
      !c ||
      c.applicationId !== row.applicationId ||
      c.environmentId !== row.environmentId ||
      this.incidents.has(row.id) ||
      row.version !== 1 ||
      row.state !== 'open' ||
      row.acknowledgedAt ||
      row.resolvedAt
    )
      throw new Error('incident_invalid');
    if (row.source === 'automatic_rule') {
      const rule = await this.findAlertRule(row.orgId, row.ruleId ?? '');
      if (
        !rule ||
        rule.componentId !== row.componentId ||
        rule.applicationId !== row.applicationId ||
        rule.environmentId !== row.environmentId
      )
        throw new Error('incident_rule_parent');
    } else if (row.source !== 'manual_triage' || row.ruleId) throw new Error('incident_source');
    if (
      [...this.incidents.values()].some(
        (r) =>
          r.orgId === row.orgId &&
          r.componentId === row.componentId &&
          r.source === row.source &&
          r.ruleId === row.ruleId &&
          r.state !== 'resolved',
      )
    )
      throw new Error('incident_conflict');
    this.incidents.set(row.id, structuredClone(row));
  }
  async updateIncident(row: Incident, expectedVersion: number) {
    const old = await this.findIncident(row.orgId, row.id);
    if (
      !old ||
      old.version !== expectedVersion ||
      row.version !== old.version + 1 ||
      old.state === 'resolved' ||
      row.updatedAt < old.updatedAt ||
      (old.state === 'acknowledged' && row.state === 'open') ||
      (old.acknowledgedAt && +old.acknowledgedAt !== +(row.acknowledgedAt ?? 0)) ||
      (row.state === 'acknowledged' && !row.acknowledgedAt) ||
      (row.state === 'open' && row.acknowledgedAt) ||
      (row.state === 'resolved') !== !!row.resolvedAt
    )
      throw new Error('incident_invalid');
    for (const key of [
      'orgId',
      'applicationId',
      'environmentId',
      'componentId',
      'source',
      'ruleId',
      'severity',
      'createdByUserId',
      'createdAt',
    ] as const)
      if (key === 'createdAt' ? +row.createdAt !== +old.createdAt : row[key] !== old[key])
        throw new Error('incident_immutable');
    this.incidents.set(row.id, structuredClone(row));
  }
  override async recordHeartbeat(row: Heartbeat) {
    const c = await this.find('component', row.orgId, row.componentId);
    if (!c || c.applicationId !== row.applicationId || c.environmentId !== row.environmentId)
      throw new Error('heartbeat_parent');
    await super.recordHeartbeat(row);
  }
  override async insertEvent(row: OperationEvent) {
    const component = await this.find('component', row.orgId, row.componentId);
    const credential = await this.findCredential(row.credentialId);
    if (
      !component ||
      component.applicationId !== row.applicationId ||
      component.environmentId !== row.environmentId ||
      !credential ||
      credential.orgId !== row.orgId ||
      credential.applicationId !== row.applicationId ||
      credential.environmentId !== row.environmentId
    )
      throw new Error('event_parent');
    await super.insertEvent(row);
  }
  credentials = new Map<string, CredentialRecord>();
  async findCredential(id: string) {
    const row = this.credentials.get(id);
    return row ? structuredClone(row) : undefined;
  }
  async listCredentials(scope: CredentialScope, options: CredentialListOptions) {
    return [...this.credentials.values()]
      .filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId &&
          (!options.after || r.id > options.after) &&
          (!options.activeAt || (!r.revokedAt && r.expiresAt > options.activeAt)),
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, options.limit)
      .map((r) => structuredClone(r));
  }
  async insertCredential(row: CredentialRecord) {
    const env = await this.find('environment', row.orgId, row.environmentId);
    if (!env || env.applicationId !== row.applicationId) throw new Error('credential_parent');
    if (this.credentials.has(row.id)) throw new Error('duplicate_credential');
    this.credentials.set(row.id, structuredClone(row));
  }
  async updateCredential(row: CredentialRecord) {
    const old = await this.findCredential(row.id);
    if (
      !old ||
      old.orgId !== row.orgId ||
      old.applicationId !== row.applicationId ||
      old.environmentId !== row.environmentId ||
      old.secretHash !== row.secretHash ||
      old.purpose !== row.purpose ||
      old.source !== row.source ||
      +old.createdAt !== +row.createdAt ||
      row.expiresAt > old.expiresAt ||
      (old.revokedAt && (!row.revokedAt || +old.revokedAt !== +row.revokedAt)) ||
      (old.rotatedAt && (!row.rotatedAt || +old.rotatedAt !== +row.rotatedAt))
    )
      throw new Error('credential_immutable');
    this.credentials.set(row.id, structuredClone(row));
  }
  rows: { [K in InventoryType]: Map<string, InventoryEntities[K]> } = {
    application: new Map(),
    environment: new Map(),
    component: new Map(),
  };
  async find<K extends InventoryType>(
    type: K,
    orgId: string,
    id: string,
  ): Promise<InventoryEntities[K] | undefined> {
    const row = this.rows[type].get(id);
    return row?.orgId === orgId ? structuredClone(row) : undefined;
  }
  async list<K extends InventoryType>(
    type: K,
    scope: InventoryScope,
  ): Promise<InventoryEntities[K][]> {
    return [...this.rows[type].values()]
      .filter(
        (row) =>
          row.orgId === scope.orgId &&
          (!scope.applicationId ||
            ('applicationId' in row && row.applicationId === scope.applicationId)) &&
          (!scope.environmentId ||
            ('environmentId' in row && row.environmentId === scope.environmentId)),
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map((row) => structuredClone(row));
  }
  async insert<K extends InventoryType>(type: K, row: InventoryEntities[K]) {
    const scope = {
      orgId: row.orgId,
      ...('applicationId' in row ? { applicationId: row.applicationId } : {}),
      ...('environmentId' in row ? { environmentId: row.environmentId } : {}),
    };
    if (
      this.rows[type].has(row.id) ||
      (await this.list(type, scope)).some((r) => r.code === row.code)
    )
      throw new Error('duplicate_inventory');
    if ('applicationId' in row && !(await this.find('application', row.orgId, row.applicationId)))
      throw new Error('inventory_parent');
    if ('environmentId' in row) {
      const parent = await this.find('environment', row.orgId, row.environmentId);
      if (!parent || parent.applicationId !== row.applicationId)
        throw new Error('inventory_parent');
    }
    this.rows[type].set(row.id, structuredClone(row));
  }
  async update<K extends InventoryType>(
    type: K,
    row: InventoryEntities[K],
    expectedVersion: number,
  ) {
    const old = await this.find(type, row.orgId, row.id);
    if (!old || old.version !== expectedVersion || row.version !== old.version + 1)
      throw new Error('inventory_version');
    if (
      old.code !== row.code ||
      ('applicationId' in old && old.applicationId !== (row as typeof old).applicationId) ||
      ('environmentId' in old && old.environmentId !== (row as typeof old).environmentId)
    )
      throw new Error('inventory_immutable');
    if (old.state === 'archived') throw new Error('inventory_archived');
    this.rows[type].set(row.id, structuredClone(row));
  }
}
export class InMemoryInventoryStore extends Repo implements InventoryStore {
  #tail: Promise<unknown> = Promise.resolve();
  readonly committedAudit: AuditEventInput[] = [];
  readonly #audit?: AuditLog;
  constructor(options?: { audit?: AuditLog }) {
    super();
    this.#audit = options?.audit;
  }
  transaction<T>(_orgId: string, fn: (tx: InventoryTx) => Promise<T>): Promise<T> {
    const run = async () => {
      // Work against an isolated snapshot: readers cannot see uncommitted rows.
      const repo = new Repo();
      repo.securityEvidence = structuredClone(this.securityEvidence);
      repo.securityFindings = structuredClone(this.securityFindings);
      repo.rows = structuredClone(this.rows);
      repo.credentials = structuredClone(this.credentials);
      repo.events = structuredClone(this.events);
      repo.eventCounters = structuredClone(this.eventCounters);
      repo.eventAggregates = structuredClone(this.eventAggregates);
      repo.heartbeats = structuredClone(this.heartbeats);
      repo.healthClocks = structuredClone(this.healthClocks);
      repo.incidents = structuredClone(this.incidents);
      repo.rules = structuredClone(this.rules);
      repo.notifications = structuredClone(this.notifications);
      const buffer = new AuditBuffer();
      const out = await fn(Object.assign(repo, { audit: buffer }));
      const events = buffer.drain();
      if (this.#audit) await this.#audit.appendMany(events);
      else this.committedAudit.push(...events);
      this.securityEvidence = repo.securityEvidence;
      this.securityFindings = repo.securityFindings;
      this.rows = repo.rows;
      this.credentials = repo.credentials;
      this.events = repo.events;
      this.eventCounters = repo.eventCounters;
      this.eventAggregates = repo.eventAggregates;
      this.heartbeats = repo.heartbeats;
      this.healthClocks = repo.healthClocks;
      this.incidents = repo.incidents;
      this.rules = repo.rules;
      this.notifications = repo.notifications;
      return out;
    };
    const result = this.#tail.then(run, run);
    this.#tail = result.catch(() => undefined);
    return result;
  }
}
