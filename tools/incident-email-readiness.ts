import type { PlatformConfig } from '../services/platform-api/src/config.ts';

export interface RecipientEvidence {
  accountExists: boolean;
  emailVerified: boolean;
  enabledRules: number;
  pending: number;
  claimed: number;
  delivered: number;
  failed: number;
}

/** Fixed metadata only. A delivered outbox row does not identify its transport or prove inbox receipt. */
export function incidentEmailReadiness(
  config: Pick<
    PlatformConfig,
    'operationsAutomationEnabled' | 'operationsEmailNotificationsEnabled' | 'emailDelivery'
  >,
  evidence: RecipientEvidence,
) {
  const checks = {
    automation_enabled: config.operationsAutomationEnabled,
    incident_email_enabled: config.operationsEmailNotificationsEnabled,
    provider_configured: config.emailDelivery !== undefined,
    recipient_exists: evidence.accountExists,
    recipient_verified: evidence.emailVerified,
    recipient_has_enabled_rules: evidence.enabledRules > 0,
  };
  return {
    checks,
    ready_for_controlled_test: Object.values(checks).every(Boolean),
    notification_counts: {
      pending: evidence.pending,
      claimed: evidence.claimed,
      delivered: evidence.delivered,
      failed: evidence.failed,
    },
    inbox_delivery: 'not_verified',
    historical_delivery_transport: 'not_recorded',
  };
}
