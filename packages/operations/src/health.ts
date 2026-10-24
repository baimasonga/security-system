import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type { CredentialScope, InventoryStore, InventoryTx } from './model.ts';
import type { EventAggregate, OperationEvent } from './events-model.ts';
export type ReportStatus = 'healthy' | 'unknown' | 'degraded' | 'unavailable';
export type HealthStatus = ReportStatus | 'stale';
export const HEARTBEAT_RANK: Record<ReportStatus, number> = {
  healthy: 0,
  unknown: 1,
  degraded: 2,
  unavailable: 3,
};
export interface Heartbeat extends CredentialScope {
  componentId: string;
  status: ReportStatus;
  occurredAt: Date;
  receivedAt: Date;
  expiresAt: Date;
}
/** Latest outside-in check made by Warrior itself; never a backend report (ADR-029 probes). */
export interface ProbeResult extends CredentialScope {
  componentId: string;
  status: 'healthy' | 'unavailable';
  occurredAt: Date;
  receivedAt: Date;
  expiresAt: Date;
}
export interface HealthRepo {
  observeHealthTime(orgId: string, now: Date): Promise<Date>;
  recordHeartbeat(row: Heartbeat): Promise<void>;
  getHeartbeat(scope: CredentialScope, componentId: string): Promise<Heartbeat | undefined>;
  /** Latest occurrence wins; equal occurrences prefer unavailable. */
  recordProbeResult(row: ProbeResult): Promise<void>;
  getProbeResult(scope: CredentialScope, componentId: string): Promise<ProbeResult | undefined>;
  listHealthHistory(
    scope: CredentialScope,
    componentId: string,
    from: Date,
    to: Date,
    now: Date,
  ): Promise<EventAggregate[]>;
}
export function eligibleHeartbeat(e: OperationEvent): Heartbeat | undefined {
  if (e.type !== 'component.heartbeat') return;
  const occurredAt = new Date(e.occurredAt),
    age = +e.receivedAt - +occurredAt;
  if (age < 0 || age > 120000) return;
  return {
    orgId: e.orgId,
    applicationId: e.applicationId,
    environmentId: e.environmentId,
    componentId: e.componentId,
    status: e.attributes['status'] as ReportStatus,
    occurredAt,
    receivedAt: e.receivedAt,
    expiresAt: e.expiresAt,
  };
}
export class HealthService {
  readonly #d: {
    store: InventoryStore;
    clock: Clock;
    enabled(): boolean;
    authorize(p: UserPrincipal, orgId: string, tx?: InventoryTx): Promise<void>;
  };
  constructor(d: {
    store: InventoryStore;
    clock: Clock;
    enabled(): boolean;
    authorize(p: UserPrincipal, orgId: string, tx?: InventoryTx): Promise<void>;
  }) {
    this.#d = d;
  }
  async #read<T>(p: UserPrincipal, scope: CredentialScope, fn: (tx: InventoryTx) => Promise<T>) {
    if (!this.#d.enabled()) throw new DomainError('not_found', 'not found');
    await this.#d.authorize(p, scope.orgId);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await this.#d.authorize(p, scope.orgId, tx);
      const a = await tx.find('application', scope.orgId, scope.applicationId),
        e = await tx.find('environment', scope.orgId, scope.environmentId);
      if (!a || !e || e.applicationId !== a.id) throw new DomainError('not_found', 'not found');
      return fn(tx);
    });
  }
  async snapshot(p: UserPrincipal, scope: CredentialScope) {
    return this.#read(p, scope, async (tx) => {
      const now = await tx.observeHealthTime(scope.orgId, this.#d.clock.now());
      const a = (await tx.find('application', scope.orgId, scope.applicationId))!;
      const e = (await tx.find('environment', scope.orgId, scope.environmentId))!;
      const components = await tx.list('component', scope);
      // A record counts only if it is unexpired, not from the future and newer than the
      // latest change to its application, environment and component.
      const current = <T extends { occurredAt: Date; receivedAt: Date; expiresAt: Date }>(
        r: T | undefined,
        c: { version: number; updatedAt: Date },
      ) =>
        r &&
        r.expiresAt > now &&
        r.receivedAt <= now &&
        r.occurredAt <= now &&
        [a, e, c].every((resource) =>
          resource.version === 1
            ? r.occurredAt >= resource.updatedAt
            : r.occurredAt > resource.updatedAt,
        )
          ? r
          : undefined;
      const rows = await Promise.all(
        components.map(async (c) => {
          const eligible = current(await tx.getHeartbeat(scope, c.id), c);
          // Warrior's own check, shown beside the backend report; it never changes `status`.
          const probe = current(await tx.getProbeResult(scope, c.id), c);
          const active = a.state === 'active' && e.state === 'active' && c.state === 'active';
          const status: HealthStatus =
            !active || !eligible
              ? 'unknown'
              : +now - +eligible.receivedAt >= 180000
                ? 'stale'
                : eligible.status;
          return {
            monitoringActive: active,
            id: c.id,
            code: c.code,
            state: c.state,
            reportedStatus: status,
            status,
            source: 'backend_report' as const,
            occurredAt: eligible?.occurredAt ?? null,
            receivedAt: eligible?.receivedAt ?? null,
            lastAssertion: eligible?.status ?? null,
            probe: {
              status: (!active || !probe
                ? 'unknown'
                : +now - +probe.receivedAt >= 180000
                  ? 'stale'
                  : probe.status) as 'healthy' | 'unavailable' | 'stale' | 'unknown',
              occurredAt: probe?.occurredAt ?? null,
              receivedAt: probe?.receivedAt ?? null,
            },
            dependencyIds: c.dependencyIds,
          };
        }),
      );
      const byId = new Map(rows.map((r) => [r.id, r]));
      const resolved = new Map<string, HealthStatus>();
      const resolve = (id: string, seen = new Set<string>()): HealthStatus => {
        const row = byId.get(id);
        if (!row || !row.monitoringActive || seen.has(id)) return 'unknown';
        if (resolved.has(id)) return resolved.get(id)!;
        seen.add(id);
        const deps = row.dependencyIds.map((d) => resolve(d, new Set(seen)));
        const status: HealthStatus =
          row.reportedStatus === 'unavailable' || deps.includes('unavailable')
            ? 'unavailable'
            : row.reportedStatus === 'healthy' && deps.some((s) => s !== 'healthy')
              ? 'degraded'
              : row.reportedStatus;
        resolved.set(id, status);
        return status;
      };
      return {
        asOf: now,
        heartbeatIntervalSeconds: 60,
        staleAfterSeconds: 180,
        independentProbe: false,
        components: rows.map(({ monitoringActive: _active, ...r }) => ({
          ...r,
          status: resolve(r.id),
          dependencies: r.dependencyIds.map((id) => ({ id, status: resolve(id) })),
        })),
      };
    });
  }
  async history(
    p: UserPrincipal,
    scope: CredentialScope,
    componentId: string,
    from: Date,
    to: Date,
  ) {
    const now = this.#d.clock.now();
    if (
      !Number.isFinite(+from) ||
      !Number.isFinite(+to) ||
      to <= from ||
      +to - +from > 86400000 ||
      to > now ||
      +from < +now - 90 * 86400000
    )
      throw new DomainError('invalid_request', 'request rejected');
    return this.#read(p, scope, async (tx) => {
      const c = await tx.find('component', scope.orgId, componentId);
      if (!c || c.applicationId !== scope.applicationId || c.environmentId !== scope.environmentId)
        throw new DomainError('not_found', 'not found');
      const rows = await tx.listHealthHistory(scope, componentId, from, to, now);
      return {
        from,
        to,
        coverage: 'observations_only' as const,
        bucketSeconds: 3600,
        partialBoundaryBuckets: +from % 3600000 !== 0 || +to % 3600000 !== 0,
        truncated: rows.length > 1000,
        items: rows.slice(0, 1000).map((r) => ({
          hour: r.hour,
          type: r.type,
          outcome: r.outcome,
          count: r.count,
          source: 'backend_report' as const,
        })),
      };
    });
  }
}
