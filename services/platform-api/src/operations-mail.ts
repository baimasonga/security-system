import type { AlertNotification, InventoryStore } from '@trust/operations';
import type { MailDelivery } from './integrations/mail.ts';

/**
 * Email transport for automatic incident notifications (ADR-029 amendment, 24 October 2026).
 * The destination is the notification's fixed recipient: their verified account address, looked up
 * here at send time. Messages carry only inventory codes, enumerated values, identifiers and a link
 * to the fixed portal origin; never event attributes, provider output or caller-supplied text.
 */
export function incidentEmailDelivery(d: {
  store: InventoryStore;
  contact(userId: string): Promise<{ email: string; emailVerified: boolean } | undefined>;
  mail: MailDelivery;
  publicOrigin: string;
}) {
  return async (n: Readonly<AlertNotification>) => {
    // Read-only and re-runnable; the claim fence is checked by the caller after sending.
    const facts = await d.store.transaction(n.orgId, async (tx) => {
      const incident = await tx.findIncident(n.orgId, n.incidentId);
      if (
        !incident ||
        incident.applicationId !== n.applicationId ||
        incident.environmentId !== n.environmentId
      )
        return;
      // Sequential: one transaction connection runs one query at a time.
      const a = await tx.find('application', n.orgId, n.applicationId),
        e = await tx.find('environment', n.orgId, n.environmentId),
        c = await tx.find('component', n.orgId, incident.componentId),
        rule = incident.ruleId ? await tx.findAlertRule(n.orgId, incident.ruleId) : undefined;
      if (!a || !e || !c) return;
      return { incident, a, e, c, runbook: rule?.runbook ?? null };
    });
    if (!facts) throw new Error('notification subject unavailable');
    const contact = await d.contact(n.recipientUserId);
    // Only an address its owner has proven receives incident details.
    if (!contact?.emailVerified) throw new Error('recipient has no verified email');
    const { incident, a, e, c, runbook } = facts;
    const opened = n.transition === 'opened';
    const where = `${a.code}/${e.code}/${c.code}`;
    await d.mail.send({
      id: n.id,
      to: contact.email,
      subject: opened
        ? `Warrior incident opened: ${incident.severity} on ${where}`
        : `Warrior incident resolved on ${where}`,
      text: [
        opened
          ? 'An automatic Warrior rule opened an incident.'
          : 'An automatic Warrior incident was resolved after fresh healthy reports.',
        '',
        `Application: ${a.code}`,
        `Environment: ${e.code}`,
        `Component: ${c.code}`,
        `Severity: ${incident.severity}`,
        ...(runbook ? [`Runbook: ${runbook}`] : []),
        `Incident: ${incident.id}`,
        `Time: ${n.createdAt.toISOString()}`,
        '',
        `Review it in Warrior: ${d.publicOrigin}/`,
        '',
        'You receive this because you created the alert rule.',
        'Warrior never asks for your password or sign-in codes by email.',
      ].join('\n'),
    });
  };
}
