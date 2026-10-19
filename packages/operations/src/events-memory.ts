import { HEARTBEAT_RANK, type Heartbeat } from './health.ts';
import type { CredentialScope } from './model.ts';
import type { EventAggregate, EventCounter, OperationEvent } from './events-model.ts';
const key = (scope: CredentialScope, id: string) =>
  JSON.stringify([scope.orgId, scope.applicationId, scope.environmentId, id]);
export class MemoryEventRepo {
  heartbeats = new Map<string, Heartbeat>();
  async recordHeartbeat(row: Heartbeat) {
    if (
      !Number.isFinite(+row.occurredAt) ||
      !Number.isFinite(+row.receivedAt) ||
      row.occurredAt > row.receivedAt ||
      +row.receivedAt - +row.occurredAt > 120000 ||
      row.expiresAt <= row.receivedAt
    )
      throw new Error('invalid_heartbeat');
    const id = key(row, row.componentId),
      old = this.heartbeats.get(id);
    if (
      !old ||
      row.occurredAt > old.occurredAt ||
      (+row.occurredAt === +old.occurredAt &&
        HEARTBEAT_RANK[row.status] > HEARTBEAT_RANK[old.status])
    )
      this.heartbeats.set(id, structuredClone(row));
  }
  async getHeartbeat(scope: CredentialScope, componentId: string) {
    return structuredClone(this.heartbeats.get(key(scope, componentId)));
  }
  async listHealthHistory(
    scope: CredentialScope,
    componentId: string,
    from: Date,
    to: Date,
    now: Date,
  ) {
    const start = Math.floor(+from / 3600000) * 3600000;
    return [...this.eventAggregates.values()]
      .filter(
        (r) =>
          r.orgId === scope.orgId &&
          r.applicationId === scope.applicationId &&
          r.environmentId === scope.environmentId &&
          r.componentId === componentId &&
          +r.hour >= start &&
          r.hour < to &&
          r.expiresAt > now,
      )
      .sort(
        (a, b) =>
          +a.hour - +b.hour || a.type.localeCompare(b.type) || a.outcome.localeCompare(b.outcome),
      )
      .slice(0, 1001)
      .map((r) => structuredClone(r));
  }
  events = new Map<string, OperationEvent>();
  eventCounters = new Map<string, EventCounter>();
  eventAggregates = new Map<string, EventAggregate>();
  async findEvent(scope: CredentialScope, id: string) {
    return structuredClone(this.events.get(key(scope, id)));
  }
  async insertEvent(row: OperationEvent) {
    const id = key(row, row.id);
    if (this.events.has(id)) throw new Error('duplicate_event');
    this.events.set(id, structuredClone(row));
  }
  async getEventCounter(orgId: string, id: string) {
    return structuredClone(this.eventCounters.get(JSON.stringify([orgId, id])));
  }
  async putEventCounter(row: EventCounter) {
    this.eventCounters.set(JSON.stringify([row.orgId, row.key]), structuredClone(row));
  }
  async getEventAggregate(
    scope: CredentialScope,
    componentId: string,
    type: string,
    hour: Date,
    outcome: string,
  ) {
    return structuredClone(
      this.eventAggregates.get(key(scope, JSON.stringify([componentId, type, +hour, outcome]))),
    );
  }
  async addEventAggregate(row: EventAggregate) {
    const id = key(row, JSON.stringify([row.componentId, row.type, +row.hour, row.outcome]));
    const old = this.eventAggregates.get(id);
    this.eventAggregates.set(id, structuredClone({ ...row, count: (old?.count ?? 0) + row.count }));
  }
  async pruneEventRows(orgId: string, now: Date, limit: number) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
      throw new Error('invalid retention limit');
    const rows = [...this.events.entries()]
      .filter(([, r]) => r.orgId === orgId && r.expiresAt <= now)
      .sort(([, a], [, b]) => +a.expiresAt - +b.expiresAt)
      .slice(0, limit);
    for (const [id] of rows) this.events.delete(id);
    return rows.map(([, r]) => structuredClone(r));
  }
  async pruneEventMetadata(orgId: string, now: Date, limit: number) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
      throw new Error('invalid retention limit');
    for (const map of [this.eventCounters, this.eventAggregates, this.heartbeats]) {
      let deleted = 0;
      for (const [id, row] of map)
        if (row.orgId === orgId && row.expiresAt && row.expiresAt <= now && deleted < limit) {
          map.delete(id);
          deleted++;
        }
    }
  }
  async expiredEventOrganizations(now: Date, limit: number) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
      throw new Error('invalid retention limit');
    return [
      ...new Set(
        [
          ...this.events.values(),
          ...this.eventCounters.values(),
          ...this.eventAggregates.values(),
          ...this.heartbeats.values(),
        ]
          .filter((r) => r.expiresAt && r.expiresAt <= now)
          .map((r) => r.orgId),
      ),
    ]
      .sort()
      .slice(0, limit);
  }
}
