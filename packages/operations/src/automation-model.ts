import type { CredentialScope } from './model.ts';
import type { IncidentSeverity } from './incidents.ts';
export const ALERT_EVENTS = [
  'upload.failed',
  'conversion.failed',
  'scanner.unavailable',
  'malware.detected',
  'email.delivery_failed',
] as const;
export const RUNBOOKS = [
  'investigate_component',
  'check_scanner',
  'check_converter',
  'check_storage',
  'check_email',
] as const;
export interface AlertRule extends CredentialScope {
  id: string;
  componentId: string;
  /** `probe` evaluates Warrior's own outside-in checks, never the application's reports. */
  kind: 'event_count' | 'heartbeat' | 'probe';
  eventType: (typeof ALERT_EVENTS)[number] | null;
  threshold: number;
  windowSeconds: number;
  severity: IncidentSeverity;
  runbook: (typeof RUNBOOKS)[number];
  enabled: boolean;
  maintenanceUntil: Date | null;
  createdByUserId: string;
  version: number;
  createdAt: Date;
  updatedAt: Date;
  evaluatedAt: Date | null;
  badSince: Date | null;
  recoverySince: Date | null;
  incidentId: string | null;
  observation: 'unknown' | 'healthy' | 'breaching' | 'inactive';
  observedCount: number;
}
export interface AlertNotification extends CredentialScope {
  id: string;
  incidentId: string;
  recipientUserId: string;
  transition: 'opened' | 'resolved';
  state: 'pending' | 'claimed' | 'delivered' | 'failed';
  attempts: number;
  createdAt: Date;
  availableAt: Date;
  deadline: Date;
  expiresAt: Date;
  claimToken: string | null;
  leaseUntil: Date | null;
  deliveredAt: Date | null;
}
export interface AutomationRepo {
  listAlertRules(scope: CredentialScope): Promise<AlertRule[]>;
  findAlertRule(orgId: string, id: string): Promise<AlertRule | undefined>;
  insertAlertRule(row: AlertRule): Promise<void>;
  updateAlertRule(row: AlertRule, expectedVersion: number): Promise<void>;
  automationScopes(now: Date, limit: number): Promise<CredentialScope[]>;
  countAlertEvents(
    scope: CredentialScope,
    componentId: string,
    type: string,
    from: Date,
    to: Date,
    cap: number,
  ): Promise<number>;
  listAlertNotifications(
    scope: CredentialScope,
    recipientUserId?: string,
  ): Promise<AlertNotification[]>;
  findAlertNotification(orgId: string, id: string): Promise<AlertNotification | undefined>;
  insertAlertNotification(row: AlertNotification): Promise<void>;
  updateAlertNotification(row: AlertNotification): Promise<void>;
  pruneAutomation(
    orgId: string,
    now: Date,
    limit: number,
  ): Promise<{ notifications: number; incidents: number }>;
}
