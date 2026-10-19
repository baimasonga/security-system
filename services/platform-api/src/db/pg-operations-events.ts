import type { Heartbeat } from '@trust/operations';
import type {
  CredentialScope,
  EventAggregate,
  EventCounter,
  OperationEvent,
} from '@trust/operations';
import type { Queryable } from './pg.ts';
const fromEvent = (r: Record<string, unknown>): OperationEvent => ({
  orgId: String(r.org_id),
  applicationId: String(r.application_id),
  environmentId: String(r.environment_id),
  id: String(r.id),
  componentId: String(r.component_id),
  credentialId: String(r.credential_id),
  source: 'backend_report',
  type: String(r.type),
  attributes: r.attributes as OperationEvent['attributes'],
  occurredAt: String(r.occurred_at),
  receivedAt: new Date(r.received_at as Date),
  expiresAt: new Date(r.expires_at as Date),
  contentHash: String(r.content_hash),
  sizeBytes: Number(r.size_bytes),
});
const scopeParams = (scope: CredentialScope) => [
  scope.orgId,
  scope.applicationId,
  scope.environmentId,
];
const bounded = (n: number) => {
  if (!Number.isInteger(n) || n < 1 || n > 1000) throw new Error('invalid retention limit');
  return n;
};
export class PgEventRepo {
  readonly #eventsQ: Queryable;
  constructor(q: Queryable) {
    this.#eventsQ = q;
  }
  async recordHeartbeat(r: Heartbeat) {
    await this.#eventsQ.query(
      `INSERT INTO operations_heartbeats(org_id,application_id,environment_id,component_id,status,occurred_at,received_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
    ON CONFLICT(org_id,application_id,environment_id,component_id) DO UPDATE SET status=EXCLUDED.status,occurred_at=EXCLUDED.occurred_at,received_at=EXCLUDED.received_at,expires_at=EXCLUDED.expires_at
    WHERE EXCLUDED.occurred_at>operations_heartbeats.occurred_at OR (EXCLUDED.occurred_at=operations_heartbeats.occurred_at AND
    CASE EXCLUDED.status WHEN 'unavailable' THEN 3 WHEN 'degraded' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END > CASE operations_heartbeats.status WHEN 'unavailable' THEN 3 WHEN 'degraded' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END)`,
      [...scopeParams(r), r.componentId, r.status, r.occurredAt, r.receivedAt, r.expiresAt],
    );
  }
  async getHeartbeat(scope: CredentialScope, componentId: string): Promise<Heartbeat | undefined> {
    const r = (
      await this.#eventsQ.query(
        'SELECT * FROM operations_heartbeats WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND component_id=$4',
        [...scopeParams(scope), componentId],
      )
    ).rows[0];
    return r
      ? {
          ...scope,
          componentId,
          status: r.status,
          occurredAt: new Date(r.occurred_at),
          receivedAt: new Date(r.received_at),
          expiresAt: new Date(r.expires_at),
        }
      : undefined;
  }
  async listHealthHistory(
    scope: CredentialScope,
    componentId: string,
    from: Date,
    to: Date,
    now: Date,
  ): Promise<EventAggregate[]> {
    const start = new Date(Math.floor(+from / 3600000) * 3600000);
    const rows = (
      await this.#eventsQ.query(
        'SELECT * FROM operations_event_aggregates WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND component_id=$4 AND hour >= $5 AND hour < $6 AND expires_at > $7 ORDER BY hour,type,outcome LIMIT 1001',
        [...scopeParams(scope), componentId, start, to, now],
      )
    ).rows;
    return rows.map((r) => ({
      ...scope,
      componentId,
      type: r.type,
      outcome: r.outcome,
      hour: new Date(r.hour),
      count: Number(r.count),
      expiresAt: new Date(r.expires_at),
    }));
  }
  async findEvent(scope: CredentialScope, id: string) {
    const r = await this.#eventsQ.query(
      'SELECT * FROM operations_events WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND id=$4',
      [...scopeParams(scope), id],
    );
    return r.rows[0] ? fromEvent(r.rows[0]) : undefined;
  }
  async insertEvent(r: OperationEvent) {
    await this.#eventsQ.query(
      'INSERT INTO operations_events(org_id,application_id,environment_id,id,component_id,credential_id,source,type,attributes,occurred_at,received_at,expires_at,content_hash,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
      [
        ...scopeParams(r),
        r.id,
        r.componentId,
        r.credentialId,
        r.source,
        r.type,
        JSON.stringify(r.attributes),
        r.occurredAt,
        r.receivedAt,
        r.expiresAt,
        r.contentHash,
        r.sizeBytes,
      ],
    );
  }
  async getEventCounter(orgId: string, key: string): Promise<EventCounter | undefined> {
    const result = await this.#eventsQ.query(
      'SELECT * FROM operations_event_counters WHERE org_id=$1 AND key=$2',
      [orgId, key],
    );
    const r = result.rows[0];
    return r
      ? {
          orgId: r.org_id,
          key: r.key,
          count: Number(r.count),
          bytes: Number(r.bytes),
          requestTimes: r.request_times.map(Number),
          expiresAt: r.expires_at ? new Date(r.expires_at) : null,
        }
      : undefined;
  }
  async putEventCounter(r: EventCounter) {
    await this.#eventsQ.query(
      'INSERT INTO operations_event_counters(org_id,key,count,bytes,request_times,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(org_id,key) DO UPDATE SET count=EXCLUDED.count,bytes=EXCLUDED.bytes,request_times=EXCLUDED.request_times,expires_at=EXCLUDED.expires_at',
      [r.orgId, r.key, r.count, r.bytes, r.requestTimes, r.expiresAt],
    );
  }
  async addEventAggregate(r: EventAggregate) {
    await this.#eventsQ.query(
      'INSERT INTO operations_event_aggregates(org_id,application_id,environment_id,component_id,type,hour,count,expires_at,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(org_id,application_id,environment_id,component_id,type,hour,outcome) DO UPDATE SET count=operations_event_aggregates.count+EXCLUDED.count',
      [...scopeParams(r), r.componentId, r.type, r.hour, r.count, r.expiresAt, r.outcome],
    );
  }
  async getEventAggregate(
    scope: CredentialScope,
    componentId: string,
    type: string,
    hour: Date,
    outcome: string,
  ): Promise<EventAggregate | undefined> {
    const r = (
      await this.#eventsQ.query(
        'SELECT * FROM operations_event_aggregates WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND component_id=$4 AND type=$5 AND hour=$6 AND outcome=$7',
        [...scopeParams(scope), componentId, type, hour, outcome],
      )
    ).rows[0];
    return r
      ? {
          ...scope,
          componentId,
          type,
          outcome,
          hour: new Date(r.hour),
          count: Number(r.count),
          expiresAt: new Date(r.expires_at),
        }
      : undefined;
  }
  async pruneEventRows(orgId: string, now: Date, limit: number) {
    const r = await this.#eventsQ.query(
      'DELETE FROM operations_events e USING (SELECT org_id,application_id,environment_id,id FROM operations_events WHERE org_id=$1 AND expires_at<=$2 ORDER BY expires_at,id LIMIT $3) old WHERE e.org_id=old.org_id AND e.application_id=old.application_id AND e.environment_id=old.environment_id AND e.id=old.id RETURNING e.*',
      [orgId, now, bounded(limit)],
    );
    return r.rows.map(fromEvent);
  }
  async pruneEventMetadata(orgId: string, now: Date, limit: number) {
    for (const table of [
      'operations_event_counters',
      'operations_event_aggregates',
      'operations_heartbeats',
    ])
      await this.#eventsQ.query(
        `DELETE FROM ${table} WHERE ctid IN (SELECT ctid FROM ${table} WHERE org_id=$1 AND expires_at<=$2 ORDER BY expires_at LIMIT $3 FOR UPDATE)`,
        [orgId, now, bounded(limit)],
      );
  }
  async expiredEventOrganizations(now: Date, limit: number) {
    // Each expiry-index scan is bounded before union/deduplication.
    const r = await this.#eventsQ.query(
      'SELECT DISTINCT org_id FROM ((SELECT org_id FROM operations_events WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2) UNION ALL (SELECT org_id FROM operations_event_counters WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2) UNION ALL (SELECT org_id FROM operations_event_aggregates WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2) UNION ALL (SELECT org_id FROM operations_heartbeats WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2)) expired ORDER BY org_id LIMIT $2',
      [now, bounded(limit)],
    );
    return r.rows.map((row) => String(row.org_id));
  }
}
