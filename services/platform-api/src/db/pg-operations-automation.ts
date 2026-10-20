import { PgEventRepo } from './pg-operations-events.ts';
import type { Queryable } from './pg.ts';
import type { AlertRule, AlertNotification, CredentialScope } from '@trust/operations';
const column = (s: string) => s.replace(/[A-Z]/g, (c) => '_' + c.toLowerCase());
const ruleFields = [
  'id',
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
  'enabled',
  'maintenanceUntil',
  'createdByUserId',
  'version',
  'createdAt',
  'updatedAt',
  'evaluatedAt',
  'badSince',
  'recoverySince',
  'incidentId',
  'observation',
  'observedCount',
] as const;
function ruleFrom(r: Record<string, unknown>): AlertRule {
  const row = Object.fromEntries(ruleFields.map((f) => [f, r[column(f)]]));
  for (const f of [
    'maintenanceUntil',
    'createdAt',
    'updatedAt',
    'evaluatedAt',
    'badSince',
    'recoverySince',
  ])
    if (row[f]) row[f] = new Date(row[f] as Date);
  return row as unknown as AlertRule;
}
const notificationFields = [
  'id',
  'orgId',
  'applicationId',
  'environmentId',
  'incidentId',
  'recipientUserId',
  'transition',
  'state',
  'attempts',
  'createdAt',
  'availableAt',
  'deadline',
  'expiresAt',
  'claimToken',
  'leaseUntil',
  'deliveredAt',
] as const;
function notificationFrom(r: Record<string, unknown>): AlertNotification {
  const row = Object.fromEntries(notificationFields.map((f) => [f, r[column(f)]]));
  for (const f of [
    'createdAt',
    'availableAt',
    'deadline',
    'expiresAt',
    'leaseUntil',
    'deliveredAt',
  ])
    if (row[f]) row[f] = new Date(row[f] as Date);
  return row as unknown as AlertNotification;
}
export class PgAutomationRepo extends PgEventRepo {
  readonly #q: Queryable;
  constructor(q: Queryable) {
    super(q);
    this.#q = q;
  }
  async findAlertRule(orgId: string, id: string) {
    const r = await this.#q.query(
      'SELECT * FROM operations_alert_rules WHERE org_id=$1 AND id=$2',
      [orgId, id],
    );
    return r.rows[0] ? ruleFrom(r.rows[0]) : undefined;
  }
  async insertAlertRule(row: AlertRule) {
    await this.#q.query(
      `INSERT INTO operations_alert_rules (${ruleFields.map(column).join(',')}) VALUES (${ruleFields.map((_, i) => '$' + (i + 1)).join(',')})`,
      ruleFields.map((f) => row[f]),
    );
  }
  async updateAlertRule(row: AlertRule, expectedVersion: number) {
    const fields = ruleFields;
    const params = [...fields.map((f) => row[f]), expectedVersion];
    const r = await this.#q.query(
      `UPDATE operations_alert_rules SET ${fields.map((f, i) => column(f) + '=$' + (i + 1)).join(',')} WHERE id=$1 AND org_id=$2 AND version=$${params.length}`,
      params,
    );
    if (r.rowCount !== 1) throw new Error('rule_version');
  }
  async findAlertNotification(orgId: string, id: string) {
    const r = await this.#q.query(
      'SELECT * FROM operations_alert_notifications WHERE org_id=$1 AND id=$2',
      [orgId, id],
    );
    return r.rows[0] ? notificationFrom(r.rows[0]) : undefined;
  }
  async insertAlertNotification(row: AlertNotification) {
    await this.#q.query(
      `INSERT INTO operations_alert_notifications (${notificationFields.map(column).join(',')}) VALUES (${notificationFields.map((_, i) => '$' + (i + 1)).join(',')})`,
      notificationFields.map((f) => row[f]),
    );
  }
  async updateAlertNotification(row: AlertNotification) {
    const fields = notificationFields;
    const r = await this.#q.query(
      `UPDATE operations_alert_notifications SET ${fields.map((f, i) => column(f) + '=$' + (i + 1)).join(',')} WHERE id=$1 AND org_id=$2 AND state NOT IN ('delivered','failed')`,
      fields.map((f) => row[f]),
    );
    if (r.rowCount !== 1) throw new Error('notification_invalid');
  }
  async listAlertRules(s: CredentialScope) {
    const r = await this.#q.query(
      'SELECT * FROM operations_alert_rules WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 ORDER BY id LIMIT 25',
      [s.orgId, s.applicationId, s.environmentId],
    );
    return r.rows.map(ruleFrom);
  }
  async listAlertNotifications(s: CredentialScope, recipientUserId?: string) {
    const r = await this.#q.query(
      'SELECT * FROM operations_alert_notifications WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND ($4::text IS NULL OR recipient_user_id=$4) ORDER BY created_at,id LIMIT 2000',
      [s.orgId, s.applicationId, s.environmentId, recipientUserId ?? null],
    );
    return r.rows.map(notificationFrom);
  }
  async automationScopes(now: Date, limit: number) {
    const r = await this.#q.query(
      `SELECT org_id,application_id,environment_id,MIN(due) AS oldest FROM (SELECT org_id,application_id,environment_id,COALESCE(evaluated_at,'epoch'::timestamptz) AS due FROM operations_alert_rules UNION ALL SELECT org_id,application_id,environment_id,available_at FROM operations_alert_notifications WHERE (state='pending' AND available_at<=$1) OR (state='claimed' AND lease_until<=$1) OR expires_at<=$1 UNION ALL SELECT org_id,application_id,environment_id,resolved_at FROM operations_incidents WHERE state='resolved' AND resolved_at<=$1-interval '365 days') q GROUP BY org_id,application_id,environment_id ORDER BY oldest,org_id,application_id,environment_id LIMIT $2`,
      [now, limit],
    );
    return r.rows.map((r) => ({
      orgId: r.org_id as string,
      applicationId: r.application_id as string,
      environmentId: r.environment_id as string,
    }));
  }
  async countAlertEvents(
    s: CredentialScope,
    componentId: string,
    type: string,
    from: Date,
    to: Date,
    cap: number,
  ) {
    const r = await this.#q.query(
      'SELECT count(*)::integer AS n FROM (SELECT 1 FROM operations_events WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND component_id=$4 AND type=$5 AND received_at>$6 AND received_at<=$7 AND expires_at>$7 LIMIT $8) q',
      [s.orgId, s.applicationId, s.environmentId, componentId, type, from, to, cap],
    );
    return Number(r.rows[0]!.n);
  }
  async pruneAutomation(orgId: string, now: Date, limit: number) {
    const n = await this.#q.query(
      'DELETE FROM operations_alert_notifications WHERE id IN (SELECT id FROM operations_alert_notifications WHERE org_id=$1 AND expires_at<=$2 AND expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT $3)',
      [orgId, now, limit],
    );
    const i = await this.#q.query(
      `DELETE FROM operations_incidents WHERE id IN (SELECT i.id FROM operations_incidents i WHERE org_id=$1 AND state='resolved' AND resolved_at<=$2 AND resolved_at<=clock_timestamp()-interval '365 days' AND NOT EXISTS (SELECT 1 FROM operations_alert_notifications n WHERE n.incident_id=i.id) ORDER BY resolved_at,id LIMIT $3)`,
      [orgId, new Date(+now - 365 * 86400000), limit],
    );
    return { notifications: n.rowCount ?? 0, incidents: i.rowCount ?? 0 };
  }
}
